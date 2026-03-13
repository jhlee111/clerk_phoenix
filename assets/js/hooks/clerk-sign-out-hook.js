export const ClerkSignOut = {
  mounted() {
    this.performSignOut();
  },

  performSignOut() {
    const redirectUrl = this.el.dataset.redirectUrl || "/auth/sign-out";

    if (!window.Clerk) {
      setTimeout(() => this.performSignOut(), 100);
      return;
    }

    window.Clerk.load().then(() => {
      return window.Clerk.signOut();
    }).then(() => {
      window.location.href = redirectUrl;
    }).catch((_err) => {
      window.location.href = redirectUrl;
    });
  }
};
