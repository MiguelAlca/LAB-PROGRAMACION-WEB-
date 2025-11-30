document.addEventListener("DOMContentLoaded", () => {
    const menuToggle = document.querySelector(".menu-toggle");
    const menu = document.querySelector(".menu");

    
    if (menuToggle && menu) {
        menuToggle.addEventListener("click", (event) => {
            menu.classList.toggle("show"); 
            event.stopPropagation(); 
        });

        
        document.addEventListener("click", (event) => {
            if (!menu.contains(event.target) && !menuToggle.contains(event.target)) {
                menu.classList.remove("show");
            }
        });
    } else {
        console.error("Error: Elementos '.menu-toggle' o '.menu' no encontrados en el DOM.");
    }
});
