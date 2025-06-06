document.addEventListener("DOMContentLoaded", function () {
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
document.getElementById("contact").addEventListener("click", submitted);
function submitted() {
    alert("Your message has been sent successfully!");
}
 const dealsContainer = document.getElementById('deals-container');
    if (dealsContainer) {
        fetch('http://127.0.0.1:5001/api/deals')
            .then(r => r.json())
            .then(deals => {
                deals.forEach(d => {
                    const card = document.createElement('div');
                    card.className = 'deal-card';
                    if (d.badge) {
                        const badge = document.createElement('div');
                        badge.className = 'badge';
                        badge.textContent = d.badge;
                        card.appendChild(badge);
                    }
                    const img = document.createElement('img');
                    img.src = d.image_url;
                    img.alt = d.title;
                    card.appendChild(img);

                    const body = document.createElement('div');
                    body.className = 'deal-card-body';
                    let html = `<h3>${d.title}</h3>`;
                    if (d.rating) html += `<div class="rating">${d.rating}</div>`;
                    if (d.description) html += `<p>${d.description}</p>`;
                    if (d.price) html += `<p>${d.price}</p>`;
                    html += `<a href="${d.link}" target="_blank">Explore</a>`;
                    body.innerHTML = html;
                    card.appendChild(body);
                    dealsContainer.appendChild(card);
                });
            })
            .catch(err => {
                dealsContainer.innerHTML = '<p>Error loading deals</p>';
                console.error(err);
            });
    }

const contactBtn = document.getElementById("contact");
if (contactBtn) {
    contactBtn.addEventListener("click", function submitted() {
        alert("Your message has been sent successfully!");
    });
}