export const ClerkAuth = {
  mounted() {
    this.initClerk();
  },

  initClerk() {
    if (!window.Clerk) {
      setTimeout(() => this.initClerk(), 100);
      return;
    }

    window.Clerk.load().then(() => {
      if (window.Clerk.user) {
        this.pushEvent("clerk:signed-in", {});
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
      if (window.Clerk) {
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
