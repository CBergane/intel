document.body.addEventListener("showToast", (event) => {
    const message = typeof event.detail === "string"
        ? event.detail
        : (event.detail?.value ?? JSON.stringify(event.detail));
    const container = document.getElementById("toast-container");
    if (!container || !message) return;

    const toast = document.createElement("div");
    toast.className = "app-toast";
    toast.textContent = message;
    container.appendChild(toast);
    requestAnimationFrame(() => { toast.style.opacity = "1"; });
    window.setTimeout(() => { toast.style.opacity = "0"; }, 1800);
    window.setTimeout(() => { toast.remove(); }, 2050);
});

(() => {
    const shell = document.getElementById("mobile-nav-shell");
    const panel = document.getElementById("mobile-nav-panel");
    const toggle = document.getElementById("mobile-nav-toggle");
    const close = document.getElementById("mobile-nav-close");
    const backdrop = document.getElementById("mobile-nav-backdrop");
    if (!shell || !panel || !toggle || !close || !backdrop) return;

    const openNav = () => {
        shell.classList.remove("hidden", "pointer-events-none");
        shell.setAttribute("aria-hidden", "false");
        requestAnimationFrame(() => {
            panel.classList.remove("translate-x-full");
            backdrop.classList.remove("opacity-0");
        });
        toggle.setAttribute("aria-expanded", "true");
        document.body.classList.add("overflow-hidden");
        close.focus();
    };

    const closeNav = () => {
        if (shell.getAttribute("aria-hidden") === "true") return;
        panel.classList.add("translate-x-full");
        backdrop.classList.add("opacity-0");
        toggle.setAttribute("aria-expanded", "false");
        shell.setAttribute("aria-hidden", "true");
        document.body.classList.remove("overflow-hidden");
        toggle.focus();
        window.setTimeout(() => {
            if (panel.classList.contains("translate-x-full")) {
                shell.classList.add("hidden", "pointer-events-none");
            }
        }, 160);
    };

    toggle.addEventListener("click", openNav);
    close.addEventListener("click", closeNav);
    backdrop.addEventListener("click", closeNav);
    shell.querySelectorAll("a").forEach((link) => link.addEventListener("click", closeNav));
    document.addEventListener("keydown", (event) => {
        const navIsOpen = shell.getAttribute("aria-hidden") === "false";
        if (event.key === "Escape" && navIsOpen) {
            closeNav();
            return;
        }
        if (event.key !== "Tab" || !navIsOpen) return;

        const focusable = Array.from(
            panel.querySelectorAll('a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])')
        ).filter((element) => element.offsetParent !== null);
        if (!focusable.length) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first.focus();
        }
    });
})();
