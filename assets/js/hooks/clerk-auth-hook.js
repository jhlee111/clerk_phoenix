export const ClerkAuth = {
  mounted() {
    this.isSatellite = this.el.dataset.isSatellite === "true";
    this.initClerk();
  },

  initClerk() {
    if (this.isSatellite) {
      this._initSatellite();
    } else {
      this._initNormal();
    }
  },

  _initNormal() {
    // Wait for Clerk to be auto-initialized by the script tag (object, not constructor)
    if (!window.Clerk || typeof window.Clerk !== "object") {
      setTimeout(() => this._initNormal(), 100);
      return;
    }

    window.Clerk.load().then(() => {
      this._onClerkReady();
    }).catch((err) => {
      console.error("Clerk load error:", err);
      this.pushEvent("clerk:error", { error: err.message || "Failed to load Clerk" });
    });
  },

  _initSatellite() {
    // Wait for the Clerk SDK script to load
    if (!window.Clerk) {
      setTimeout(() => this._initSatellite(), 100);
      return;
    }

    // If Clerk is already an initialized instance (by global init script or another hook),
    // call .load() to ensure components are ready before mounting widgets
    if (typeof window.Clerk === "object") {
      window.Clerk.load().then(() => {
        this._onClerkReady();
      }).catch((err) => {
        console.error("Clerk satellite load error:", err);
        this.pushEvent("clerk:error", { error: err.message || "Failed to load Clerk satellite" });
      });
      return;
    }

    // If global init is already in progress, wait for it
    if (window.__clerkSatelliteInitPromise) {
      window.__clerkSatelliteInitPromise.then(() => {
        this._onClerkReady();
      }).catch((err) => {
        console.error("Clerk satellite init error:", err);
        this.pushEvent("clerk:error", { error: err.message || "Failed to load Clerk satellite" });
      });
      return;
    }

    // Manual instantiation for satellite domain — Clerk is a constructor function
    const publishableKey = this.el.dataset.publishableKey;
    const domain = this.el.dataset.domain || window.location.host;
    const primarySignInUrl = this.el.dataset.primarySignInUrl;

    const clerk = new window.Clerk(publishableKey);

    window.__clerkSatelliteInitPromise = clerk.load({
      isSatellite: true,
      domain: domain,
      signInUrl: primarySignInUrl
    }).then(() => {
      // Replace the constructor on window with the initialized instance
      window.Clerk = clerk;
      this._onClerkReady();
    }).catch((err) => {
      console.error("Clerk satellite load error:", err);
      this.pushEvent("clerk:error", { error: err.message || "Failed to load Clerk satellite" });
    });
  },

  _onClerkReady() {
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
