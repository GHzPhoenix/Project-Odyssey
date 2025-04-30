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

    // Dropdown for mobile
    document.querySelectorAll("nav ul li > a").forEach(link => {
        link.addEventListener("click", function (e) {
            if (this.nextElementSibling && this.nextElementSibling.classList.contains("dropdown")) {
                e.preventDefault();
                this.nextElementSibling.style.display =
                    this.nextElementSibling.style.display === "block" ? "none" : "block";
            }
        });
    });

    // Booking Form Validation
    const bookingForm = document.getElementById("booking-form");
    if (bookingForm) {
        bookingForm.addEventListener("submit", function (event) {
            event.preventDefault();
            const checkinDate = document.getElementById("checkin-date").value;
            const checkoutDate = document.getElementById("checkout-date").value;

            if (!checkinDate || !checkoutDate) {
                alert("Please fill in all date fields.");
                return;
            }

            if (new Date(checkinDate) >= new Date(checkoutDate)) {
                alert("Check-out date must be later than check-in date.");
                return;
            }

            alert("Booking submitted successfully!");
            bookingForm.reset();
        });
    }

    // Dynamic Carousel
    const carousel = document.querySelector(".carousel");
    if (carousel) {
        let carouselInterval = setInterval(() => {
            const nextButton = carousel.querySelector(".carousel-control-next");
            if (nextButton) nextButton.click();
        }, 5000);

        carousel.addEventListener("mouseenter", () => clearInterval(carouselInterval));
        carousel.addEventListener("mouseleave", () => {
            carouselInterval = setInterval(() => {
                const nextButton = carousel.querySelector(".carousel-control-next");
                if (nextButton) nextButton.click();
            }, 5000);
        });
    }

    // Destination Search Suggestions
    const destinationsList = ['London', 'Paris', 'Madrid', 'New York', 'Tokyo', 'Sydney'];
    const searchInput = document.querySelector('input[type="search"]');
    if (searchInput) {
        const suggestionsBox = document.createElement('div');
        suggestionsBox.style.position = 'absolute';
        suggestionsBox.style.border = '1px solid #ccc';
        suggestionsBox.style.backgroundColor = '#fff';
        suggestionsBox.style.zIndex = '1000';
        suggestionsBox.style.width = '90%';
        suggestionsBox.style.display = 'none';
        searchInput.parentNode.appendChild(suggestionsBox);

        searchInput.addEventListener('input', () => {
            const query = searchInput.value.toLowerCase();
            suggestionsBox.innerHTML = '';
            if (query) {
                const suggestions = destinationsList.filter(destination =>
                    destination.toLowerCase().includes(query)
                );
                suggestions.forEach(suggestion => {
                    const suggestionItem = document.createElement('div');
                    suggestionItem.textContent = suggestion;
                    suggestionItem.style.padding = '5px';
                    suggestionItem.style.cursor = 'pointer';
                    suggestionItem.addEventListener('click', () => {
                        searchInput.value = suggestion;
                        suggestionsBox.style.display = 'none';
                    });
                    suggestionsBox.appendChild(suggestionItem);
                });
                suggestionsBox.style.display = 'block';
            } else {
                suggestionsBox.style.display = 'none';
            }
        });
    }

    // Search Button Validation
    const searchButton = document.getElementById('search-button');
    if (searchButton) {
        searchButton.addEventListener('click', function () {
            const location = document.getElementById('search').value;
            if (location.trim() === '') {
                alert('Please enter a location to search.');
            } else {
                alert(`Searching for: ${location}`);
            }
        });
    }

    // Signup Form Submission
    const signupForm = document.getElementById("signup-form");
    if (signupForm) {
        signupForm.addEventListener("submit", async function (e) {
            e.preventDefault();

            const name = document.getElementById("name").value;
            const email = document.getElementById("email").value;
            const password = document.getElementById("password").value;

            try {
                const res = await fetch("http://127.0.0.1:5000/api/register", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ name, email, password }),
                });

                const data = await res.json();

                if (res.ok) {
                    alert("✅ Registration successful!");
                    window.location.href = "client-area.html";
                } else {
                    alert(data.error || "Registration failed.");
                }
            } catch (err) {
                console.error(err);
                alert("Server error. Try again later.");
            }
        });
    }
});
