// Form Validation
document.getElementById("booking-form").addEventListener("submit", function(event) {
    event.preventDefault(); // Prevent form submission for validation

    const checkinDate = document.getElementById("checkin-date").value;
    const checkoutDate = document.getElementById("checkout-date").value;

    if (new Date(checkinDate) >= new Date(checkoutDate)) {
        alert("Check-out date must be later than check-in date.");
        return;
    }

    alert("Form submitted successfully!");
});

// Dynamic Carousel Control
const carousel = document.querySelector('.carousel');
let carouselInterval = setInterval(() => {
    const nextButton = carousel.querySelector('.carousel-control-next');
    nextButton.click(); // Programmatically click the "Next" button
}, 5000);

// Stop carousel on hover
carousel.addEventListener('mouseenter', () => clearInterval(carouselInterval));
carousel.addEventListener('mouseleave', () => {
    carouselInterval = setInterval(() => {
        const nextButton = carousel.querySelector('.carousel-control-next');
        nextButton.click();
    }, 5000);
});
document.getElementById("booking-form").addEventListener("submit", function(event) {
    event.preventDefault();
    try {
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
    } catch (error) {
        console.error("An error occurred:", error);
        alert("Something went wrong. Please try again.");
    }
});

    this.reset();
    document.getElementById('checkin-date').style.border = '';
    document.getElementById('checkout-date').style.border = '';

const destinationsList = ['London', 'Paris', 'Madrid', 'New York', 'Tokyo', 'Sydney'];
const searchInput = document.querySelector('input[type="search"]');
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
document.getElementById('search-button').addEventListener('click', function () {
    const location = document.getElementById('search').value;
    if (location.trim() === '') {
        alert('Please enter a location to search.');
    } else {
        alert(`Searching for: ${location}`);
    }
});
document.addEventListener("DOMContentLoaded", function() {
    const menuToggle = document.querySelector(".menu-toggle");
    const navMenu = document.querySelector("nav ul");
    const dropdowns = document.querySelectorAll(".dropdown");

    // Toggle Mobile Menu
    menuToggle.addEventListener("click", function() {
        navMenu.classList.toggle("active");
    });

    // Close dropdown when clicking outside
    document.addEventListener("click", function(e) {
        if (!e.target.closest("nav")) {
            navMenu.classList.remove("active");
            dropdowns.forEach(dropdown => dropdown.style.display = "none");
        }
    });

    // Toggle dropdown on click (for mobile)
    document.querySelectorAll("nav ul li > a").forEach(link => {
        link.addEventListener("click", function(e) {
            if (this.nextElementSibling && this.nextElementSibling.classList.contains("dropdown")) {
                e.preventDefault();
                this.nextElementSibling.style.display =
                    this.nextElementSibling.style.display === "block" ? "none" : "block";
            }
        });
    });
});

