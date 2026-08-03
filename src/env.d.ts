/// <reference types="astro/client" />
/// <reference path="../.astro/types.d.ts" />

declare global {
	namespace astroHTML.JSX {
		interface IntrinsicAttributes {
			"client:only"?: string;
			"client:load"?: string;
			"client:idle"?: string;
			"client:visible"?: string;
			"client:media"?: string;
		}
	}
}
