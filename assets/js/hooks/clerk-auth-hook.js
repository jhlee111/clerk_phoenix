export const ClerkAuth = {
  mounted() {
    this.initClerk();
  },

  initClerk() {
    // Wait for Clerk to be auto-initialized by the script tag
    // In both normal and satellite mode, the CDN script handles initialization
    // via data attributes (data-clerk-publishable-key, data-clerk-is-satellite, etc.)
    if (!window.Clerk || typeof window.Clerk !== "object") {
      setTimeout(() => this.initClerk(), 100);
      return;
    }

    // .load() is idempotent — resolves immediately if already loaded
    window.Clerk.load().then(() => {
      if (window.Clerk.user) {
        // Direct navigation avoids redirect loops in longpoll mode
        const callbackUrl = this.el.dataset.callbackUrl || "/auth/callback";
        window.location.href = callbackUrl;
        return;
      }

      const mode = this.el.dataset.mode || "sign-in";
      const callbackUrl = this.el.dataset.callbackUrl || "/auth/callback";
      const signUpUrl = this.el.dataset.signUpUrl || "/sign-up";
      const signInUrl = this.el.dataset.signInUrl || "/sign-in";

      if (mode === "sign-in") {
        window.Clerk.mountSignIn(this.el, {
          afterSignInUrl: callbackUrl,
          signUpUrl: signUpUrl,
        });
      } else {
        window.Clerk.mountSignUp(this.el, {
          afterSignUpUrl: callbackUrl,
          signInUrl: signInUrl,
        });
      }
    }).catch((err) => {
      console.error("Clerk load error:", err);
      this.pushEvent("clerk:error", { error: err.message || "Failed to load Clerk" });
    });
  },

  destroyed() {
    try {
      if (window.Clerk && typeof window.Clerk === "object") {
        const mode = this.el.dataset.mode || "sign-in";
        if (mode === "sign-in") {
          window.Clerk.unmountSignIn(this.el);
        } else {
          window.Clerk.unmountSignUp(this.el);
        }
      }
    } catch (_e) {}
  }
};
