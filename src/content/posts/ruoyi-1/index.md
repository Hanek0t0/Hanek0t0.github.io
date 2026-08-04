---
title: RuoYi-4.8.2后台Sql注入(CVE-2026-38812)
published: 2026-08-04
description: 若依最近新爆出来的一个新day，利用难度较低。
tags: [通用系统, nday, SQL注入, 代码审计]
category: CVE复现
draft: true
---

# 漏洞描述

RuoYi是RuoYi团队开源的一款后台管理系统。 RuoYi 4.8.2版本存在安全漏洞，该漏洞源于代码生成模块中的/tool/gen/createTable端点存在SQL注入，可能导致经过身份验证的管理员权限攻击者访问敏感数据库信息。

影响版本：RuoYi v4.8.2

源码：https://github.com/yangzongzhuan/RuoYi/archive/refs/tags/v4.8.2.zip

# 源码分析

漏洞点在于 GenTableMapper.xml 文件的第168行-170行中，使用了 ${} 占位符，在Mybatis中该占位符走的是一个字符串直接拼接，而非预编译，Mybatis框架的sql注入也通常是因为这个占位符而产生。

```xml showLineNumbers startLineNumber=167 title="GenTableMapper.xml"
    
    <update id="createTable">
        ${sql}
    </update>
    
```

找到GenTableMapper.xml对应的Mapper接口，位于com.ruoyi.generator.mapper.GenTableMapper，在GenTableMapper接口中找到createTable方法。GenTableMapper.createTable(String sql)接口方法的参数会被直接拼接替换到${sql}中，有产生sql注入的嫌疑。

```java showLineNumbers startLineNumber=84 title="GenTableMapper.java"
    /**
     * 创建表
     *
     * @param sql
     * @return 结果
     */
    public int createTable(String sql);
```

Alt+F7 查调用方，只有 GenTableServiceImpl.createTable(String sql) 调了这个接口方法，参数直接透传给了GenTableMapper.createTable(String sql)。

![](img1.png)

```java showLineNumbers startLineNumber=154 title="GenTableServiceImpl.java"
    /**
     * 创建表
     *
     * @param sql 创建表语句
     * @return 结果
     */
    @Override
    public boolean createTable(String sql)
    {
        return genTableMapper.createTable(sql) == 0;
    }
```

继续向上查调用方，GenController类的create方法调用了GenTableServiceImpl.createTable(String sql)方法

![](img2.png)

我们来分析一下这个create方法。由注解@RequiresRoles可知必须要admin身份才能调用这个接口，我们可以通过POST或者GET传参直接控制create方法的参数sql。

sql 参数会先走 SqlUtil.filterKeyword 校验，如果包含危险关键字则会抛出异常，随后SQLUtils.parseStatements 把 sql 解析成语句列表(因为传入的sql可以由分号分隔成多条语句，所以返回值是一个List对象)，增强for循环遍历sqlStatements找出 MySqlCreateTableStatement对象，然后调用 createTable 建表。

为了进入if分支，传入的 sql参数必须是 CREATE  语句，若是SELECT语句，sqlStatements列表里储存的将会是MySqlSelectStatement对象，类似的CREATE语句在sqlStatements列表里储存的是MySqlCreateTableStatement对象，只有后者才能进入if分支。

genTableService.createTable(createTableStatement.toString())语句中，createTableStatement.toString()的值即为从sql参数中解析出的那条建表语句的 SQL 语句字符串。

```java {17,14} showLineNumbers startLineNumber=195 title="GenController.java"
    @RequiresRoles("admin")
    @Log(title = "创建表", businessType = BusinessType.OTHER)
    @PostMapping("/createTable")
    @ResponseBody
    public AjaxResult create(String sql)
    {
        try
        {
            SqlUtil.filterKeyword(sql);
            List<SQLStatement> sqlStatements = SQLUtils.parseStatements(sql, DbType.mysql);
            List<String> tableNames = new ArrayList<>();
            for (SQLStatement sqlStatement : sqlStatements)
            {
                if (sqlStatement instanceof MySqlCreateTableStatement)
                {
                    MySqlCreateTableStatement createTableStatement = (MySqlCreateTableStatement) sqlStatement;
                    if (genTableService.createTable(createTableStatement.toString()))
                    {
                        String tableName = createTableStatement.getTableName().replaceAll("`", "");
                        tableNames.add(tableName);
                    }
                }
            }
            List<GenTable> tableList = genTableService.selectDbTableListByNames(tableNames.toArray(new String[tableNames.size()]));
            String operName = Convert.toStr(PermissionUtils.getPrincipalProperty("loginName"));
            genTableService.importGenTable(tableList, operName);
            return AjaxResult.success();
        }
        catch (Exception e)
        {
            logger.error(e.getMessage(), e);
            return AjaxResult.error("创建表结构异常");
        }
    }
```

 SqlUtil.filterKeyword()方法对我们的sql语句进行了一次过滤，我们具体分析他的过滤逻辑。
