let map;
let directionsService;
let directionsRenderer;

// Inicializa el mapa y los servicios de Google Maps
function initMap() {
    map = new google.maps.Map(document.getElementById("map"), {
        center: { lat: 25.686614, lng: -100.316113 }, // Coordenadas de Monterrey
        zoom: 8,
    });

    directionsService = new google.maps.DirectionsService();
    directionsRenderer = new google.maps.DirectionsRenderer();
    directionsRenderer.setMap(map);
}

// Configurar el botón para calcular la ruta
document.getElementById("calcular-ruta").addEventListener("click", () => {
    const origen = document.getElementById("origen").value.trim();
    const destino = document.getElementById("destino").value.trim();

    if (!origen || !destino) {
        alert("Por favor, completa los campos de origen y destino.");
        return;
    }

    calcularRuta(origen, destino);
});

// Función para calcular la ruta
function calcularRuta(origen, destino) {
    const request = {
        origin: origen,
        destination: destino,
        travelMode: google.maps.TravelMode.DRIVING, // Modo de viaje
    };

    directionsService.route(request, (result, status) => {
        if (status === google.maps.DirectionsStatus.OK) {
            directionsRenderer.setDirections(result);
            const route = result.routes[0].legs[0];

            // Actualiza el recuadro con los resultados
            document.getElementById("distancia").textContent = `Distancia: ${route.distance.text}`;
            document.getElementById("duracion").textContent = `Duración: ${route.duration.text}`;
            document.getElementById("resultado").style.display = "block";
        } else {
            alert("No se pudo calcular la ruta: " + status);
        }
    });
}

// Cargar el mapa al inicio
window.onload = initMap;
