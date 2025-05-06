document.addEventListener("DOMContentLoaded", function () {
    // Mobile Menu Toggle
    const menuToggle = document.querySelector(".menu-toggle");
    const navMenu = document.querySelector("nav ul");

    if (menuToggle && navMenu) {
        menuToggle.addEventListener("click", function () {
            navMenu.classList.toggle("active");
        });
    }

    document.addEventListener("click", function (e) {
        if (!e.target.closest("nav")) {
            navMenu.classList.remove("active");
        }
    });


    document.querySelectorAll("nav ul li > a").forEach(link => {
        link.addEventListener("click", function (e) {
            if (this.nextElementSibling && this.nextElementSibling.classList.contains("dropdown")) {
                e.preventDefault();
                this.nextElementSibling.style.display =
                    this.nextElementSibling.style.display === "block" ? "none" : "block";
            }
        });
    });
});