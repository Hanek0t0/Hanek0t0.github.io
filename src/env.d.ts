/// <reference types="astro/client" />
/// <reference path="../.astro/types.d.ts" />

declare module '*.svelte' {
	import type { SvelteComponent } from 'svelte';
	const component: typeof SvelteComponent<Record<string, unknown>>;
	export default component;
}
