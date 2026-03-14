export const ClerkSessionMonitor = {
  mounted() {
    this.checkInterval = null;
    this.lastSessionState = null;

    const isAuthenticated = this.el.dataset.authenticated === "true";
    if (!isAuthenticated) return;

    this.startMonitoring();
  },

  startMonitoring() {
    // Wait for Clerk to be an initialized instance (not a constructor)
    if (!window.Clerk || typeof window.Clerk !== "object") {
      setTimeout(() => this.startMonitoring(), 200);
      return;
    }

    window.Clerk.load().then(() => {
      this.lastSessionState = !!window.Clerk.session;

      this.checkInterval = setInterval(() => {
        const hasSession = !!window.Clerk.session;
        if (this.lastSessionState && !hasSession) {
          console.warn("Clerk session expired or lost");
          this.pushEvent("clerk:session-expired", {});
          clearInterval(this.checkInterval);
        }
        this.lastSessionState = hasSession;
      }, 5000);

      window.Clerk.addListener(() => {
        if (this.lastSessionState && !window.Clerk.session) {
          console.warn("Clerk session change detected: signed out");
          this.pushEvent("clerk:session-expired", {});
          if (this.checkInterval) clearInterval(this.checkInterval);
        }
      });
    });
  },

  destroyed() {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
    }
  }
};
