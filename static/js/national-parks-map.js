// National Parks data with coordinates
// TO MARK A PARK AS VISITED: Change "visited: false" to "visited: true" for that park
// Parks marked as visited will show a green checkmark on the map
const nationalParks = [
  // Alaska
  { name: "Denali", lat: 63.3333, lng: -150.5000, state: "Alaska", visited: false },
  { name: "Gates of the Arctic", lat: 67.7500, lng: -153.3000, state: "Alaska", visited: false },
  { name: "Glacier Bay", lat: 58.6650, lng: -136.9000, state: "Alaska", visited: false },
  { name: "Katmai", lat: 58.5000, lng: -155.0000, state: "Alaska", visited: false },
  { name: "Kenai Fjords", lat: 59.9200, lng: -149.6500, state: "Alaska", visited: false },
  { name: "Kobuk Valley", lat: 67.5500, lng: -159.2800, state: "Alaska", visited: false },
  { name: "Lake Clark", lat: 60.9700, lng: -153.4200, state: "Alaska", visited: false },
  { name: "Wrangell-St. Elias", lat: 61.7100, lng: -142.9900, state: "Alaska", visited: false },
  
  // Arizona
  { name: "Grand Canyon", lat: 36.0544, lng: -112.1401, state: "Arizona", visited: true },
  { name: "Petrified Forest", lat: 34.9095, lng: -109.8067, state: "Arizona", visited: false },
  { name: "Saguaro", lat: 32.2500, lng: -110.5000, state: "Arizona", visited: true },
  
  // Arkansas
  { name: "Hot Springs", lat: 34.5217, lng: -93.0424, state: "Arkansas", visited: false },
  
  // California
  { name: "Channel Islands", lat: 34.0000, lng: -119.7700, state: "California", visited: false },
  { name: "Death Valley", lat: 36.5054, lng: -117.0794, state: "California", visited: false },
  { name: "Joshua Tree", lat: 33.8734, lng: -115.9010, state: "California", visited: false },
  { name: "Kings Canyon", lat: 36.8878, lng: -118.5551, state: "California", visited: true },
  { name: "Lassen Volcanic", lat: 40.4977, lng: -121.4207, state: "California", visited: false },
  { name: "Pinnacles", lat: 36.4906, lng: -121.1825, state: "California", visited: false },
  { name: "Redwood", lat: 41.2132, lng: -124.0046, state: "California", visited: false },
  { name: "Sequoia", lat: 36.4864, lng: -118.5658, state: "California", visited: true },
  { name: "Yosemite", lat: 37.8651, lng: -119.5383, state: "California", visited: false },
  
  // Colorado
  { name: "Black Canyon of the Gunnison", lat: 38.5754, lng: -107.7416, state: "Colorado", visited: false },
  { name: "Great Sand Dunes", lat: 37.7916, lng: -105.5943, state: "Colorado", visited: false },
  { name: "Mesa Verde", lat: 37.2309, lng: -108.4618, state: "Colorado", visited: false },
  { name: "Rocky Mountain", lat: 40.3428, lng: -105.6836, state: "Colorado", visited: true },
  
  // Florida
  { name: "Biscayne", lat: 25.4900, lng: -80.2100, state: "Florida", visited: false },
  { name: "Dry Tortugas", lat: 24.6285, lng: -82.8732, state: "Florida", visited: false },
  { name: "Everglades", lat: 25.2866, lng: -80.8987, state: "Florida", visited: false },
  
  // Hawaii
  { name: "Haleakalā", lat: 20.7204, lng: -156.1552, state: "Hawaii", visited: false },
  { name: "Hawaiʻi Volcanoes", lat: 19.4194, lng: -155.2885, state: "Hawaii", visited: false },
  
  // Kentucky
  { name: "Mammoth Cave", lat: 37.1862, lng: -86.1000, state: "Kentucky", visited: false },
  
  // Maine
  { name: "Acadia", lat: 44.3386, lng: -68.2733, state: "Maine", visited: false },
  
  // Michigan
  { name: "Isle Royale", lat: 47.9959, lng: -88.9092, state: "Michigan", visited: false },
  
  // Minnesota
  { name: "Voyageurs", lat: 48.5000, lng: -92.8833, state: "Minnesota", visited: false },
  
  // Missouri
  { name: "Gateway Arch", lat: 38.6247, lng: -90.1848, state: "Missouri", visited: false },
  
  // Montana
  { name: "Glacier", lat: 48.7596, lng: -113.7870, state: "Montana", visited: true },
  
  // Nevada
  { name: "Great Basin", lat: 38.9833, lng: -114.3000, state: "Nevada", visited: true },
  
  // New Mexico
  { name: "Carlsbad Caverns", lat: 32.1479, lng: -104.5567, state: "New Mexico", visited: false },
  { name: "White Sands", lat: 32.7872, lng: -106.3257, state: "New Mexico", visited: false },
  
  // North Carolina/Tennessee
  { name: "Great Smoky Mountains", lat: 35.6118, lng: -83.4895, state: "NC/TN", visited: false },
  
  // North Dakota
  { name: "Theodore Roosevelt", lat: 46.9790, lng: -103.5387, state: "North Dakota", visited: false },
  
  // Ohio
  { name: "Cuyahoga Valley", lat: 41.2808, lng: -81.5678, state: "Ohio", visited: false },
  
  // Oregon
  { name: "Crater Lake", lat: 42.8684, lng: -122.1685, state: "Oregon", visited: false },
  
  // South Carolina
  { name: "Congaree", lat: 33.7948, lng: -80.7821, state: "South Carolina", visited: false },
  
  // South Dakota
  { name: "Badlands", lat: 43.8554, lng: -102.3397, state: "South Dakota", visited: false },
  { name: "Wind Cave", lat: 43.5500, lng: -103.4833, state: "South Dakota", visited: false },
  
  // Tennessee
  { name: "Great Smoky Mountains", lat: 35.6118, lng: -83.4895, state: "Tennessee", visited: false },
  
  // Texas
  { name: "Big Bend", lat: 29.2500, lng: -103.2500, state: "Texas", visited: false },
  { name: "Guadalupe Mountains", lat: 31.9230, lng: -104.8607, state: "Texas", visited: false },
  
  // Utah
  { name: "Arches", lat: 38.7331, lng: -109.5925, state: "Utah", visited: true },
  { name: "Bryce Canyon", lat: 37.5930, lng: -112.1871, state: "Utah", visited: true },
  { name: "Canyonlands", lat: 38.2000, lng: -109.9333, state: "Utah", visited: true },
  { name: "Capitol Reef", lat: 38.3670, lng: -111.2615, state: "Utah", visited: false },
  { name: "Zion", lat: 37.2982, lng: -113.0263, state: "Utah", visited: true },
  
  // Virgin Islands
  { name: "Virgin Islands", lat: 18.3419, lng: -64.7485, state: "US Virgin Islands", visited: false },
  
  // Virginia
  { name: "Shenandoah", lat: 38.5326, lng: -78.4308, state: "Virginia", visited: false },
  
  // Washington
  { name: "Mount Rainier", lat: 46.8800, lng: -121.7269, state: "Washington", visited: true },
  { name: "North Cascades", lat: 48.7718, lng: -121.2985, state: "Washington", visited: true },
  { name: "Olympic", lat: 47.8021, lng: -123.6044, state: "Washington", visited: true },
  
  // West Virginia
  { name: "New River Gorge", lat: 37.9700, lng: -81.0700, state: "West Virginia", visited: false },
  
  // Wyoming
  { name: "Grand Teton", lat: 43.7904, lng: -110.6818, state: "Wyoming", visited: true },
  { name: "Yellowstone", lat: 44.4280, lng: -110.5885, state: "Wyoming", visited: true },
  
  // American Samoa
  { name: "American Samoa", lat: -14.2580, lng: -170.6840, state: "American Samoa", visited: false }
];

// National Monuments data with coordinates
// TO MARK A MONUMENT AS VISITED: Change "visited: false" to "visited: true" for that monument
const nationalMonuments = [
  // Alaska
  { name: "Admiralty Island", lat: 57.6667, lng: -134.4167, state: "Alaska", visited: false },
  { name: "Aniakchak", lat: 56.9000, lng: -158.1500, state: "Alaska", visited: false },
  { name: "Cape Krusenstern", lat: 67.4167, lng: -163.5000, state: "Alaska", visited: false },
  { name: "Misty Fjords", lat: 55.8333, lng: -130.5000, state: "Alaska", visited: false },
  
  // Arizona
  { name: "Agua Fria", lat: 34.1111, lng: -112.1000, state: "Arizona", visited: false },
  { name: "Canyon de Chelly", lat: 36.1531, lng: -109.5347, state: "Arizona", visited: true },
  { name: "Casa Grande Ruins", lat: 32.9967, lng: -111.5369, state: "Arizona", visited: false },
  { name: "Chiricahua", lat: 32.0094, lng: -109.3431, state: "Arizona", visited: false },
  { name: "Ironwood Forest", lat: 32.4500, lng: -111.5500, state: "Arizona", visited: false },
  { name: "Montezuma Castle", lat: 34.6114, lng: -111.8358, state: "Arizona", visited: true },
  { name: "Navajo", lat: 36.6833, lng: -110.5333, state: "Arizona", visited: false },
  { name: "Organ Pipe Cactus", lat: 31.9545, lng: -112.8003, state: "Arizona", visited: false },
  { name: "Pipe Spring", lat: 36.8631, lng: -112.7378, state: "Arizona", visited: false },
  { name: "Sonoran Desert", lat: 32.5117, lng: -112.4567, state: "Arizona", visited: true },
  { name: "Sunset Crater Volcano", lat: 35.3650, lng: -111.5650, state: "Arizona", visited: false },
  { name: "Tonto", lat: 33.6478, lng: -111.1222, state: "Arizona", visited: false },
  { name: "Tuzigoot", lat: 34.7778, lng: -112.0292, state: "Arizona", visited: true },
  { name: "Walnut Canyon", lat: 35.1711, lng: -111.5106, state: "Arizona", visited: false },
  { name: "Wupatki", lat: 35.5519, lng: -111.3681, state: "Arizona", visited: false },
  
  // California
  { name: "Berryessa Snow Mountain", lat: 39.1500, lng: -122.7000, state: "California", visited: false },
  { name: "Cabrillo", lat: 32.6728, lng: -117.2419, state: "California", visited: false },
  { name: "Caesar E. Chavez", lat: 35.2264, lng: -118.5600, state: "California", visited: false },
  { name: "Carrizo Plain", lat: 35.2500, lng: -119.6667, state: "California", visited: false },
  { name: "Castle Mountains", lat: 35.2333, lng: -115.0833, state: "California", visited: false },
  { name: "Devils Postpile", lat: 37.6311, lng: -119.0878, state: "California", visited: false },
  { name: "Giant Sequoia", lat: 36.0556, lng: -118.8278, state: "California", visited: false },
  { name: "Lava Beds", lat: 41.7133, lng: -121.5075, state: "California", visited: false },
  { name: "Mojave Trails", lat: 34.5000, lng: -115.5000, state: "California", visited: false },
  { name: "Muir Woods", lat: 37.8917, lng: -122.5808, state: "California", visited: false },
  { name: "Point Reyes", lat: 38.0667, lng: -122.8167, state: "California", visited: false },
  { name: "San Gabriel Mountains", lat: 34.2500, lng: -118.0000, state: "California", visited: false },
  { name: "Santa Rosa and San Jacinto Mountains", lat: 33.8000, lng: -116.7000, state: "California", visited: false },
  
  // Colorado
  { name: "Browns Canyon", lat: 38.6000, lng: -106.1000, state: "Colorado", visited: false },
  { name: "Canyons of the Ancients", lat: 37.3500, lng: -108.8833, state: "Colorado", visited: false },
  { name: "Chimney Rock", lat: 37.1847, lng: -107.3100, state: "Colorado", visited: false },
  { name: "Colorado", lat: 39.0833, lng: -108.6833, state: "Colorado", visited: false },
  { name: "Dinosaur", lat: 40.4397, lng: -108.9914, state: "Colorado", visited: false },
  { name: "Florissant Fossil Beds", lat: 38.9144, lng: -105.2828, state: "Colorado", visited: false },
  { name: "Hovenweep", lat: 37.3833, lng: -109.0783, state: "Colorado", visited: false },
  { name: "Yucca House", lat: 37.2489, lng: -108.6861, state: "Colorado", visited: false },
  
  // Idaho
  { name: "Craters of the Moon", lat: 43.4617, lng: -113.5167, state: "Idaho", visited: false },
  { name: "Hagerman Fossil Beds", lat: 42.7917, lng: -114.9447, state: "Idaho", visited: false },
  
  // Montana
  { name: "Little Bighorn Battlefield", lat: 45.5706, lng: -107.4306, state: "Montana", visited: false },
  { name: "Pompeys Pillar", lat: 45.9933, lng: -108.0017, state: "Montana", visited: false },
  { name: "Upper Missouri River Breaks", lat: 47.8333, lng: -109.3333, state: "Montana", visited: true },
  
  // Nevada
  { name: "Basin and Range", lat: 38.0000, lng: -115.3333, state: "Nevada", visited: false },
  { name: "Gold Butte", lat: 36.3833, lng: -114.1500, state: "Nevada", visited: false },
  { name: "Tule Springs Fossil Beds", lat: 36.3500, lng: -115.2000, state: "Nevada", visited: false },
  
  // New Mexico
  { name: "Aztec Ruins", lat: 36.8364, lng: -107.9997, state: "New Mexico", visited: false },
  { name: "Bandelier", lat: 35.7781, lng: -106.2719, state: "New Mexico", visited: false },
  { name: "Capulin Volcano", lat: 36.7819, lng: -103.9700, state: "New Mexico", visited: false },
  { name: "El Malpais", lat: 34.8811, lng: -108.0506, state: "New Mexico", visited: false },
  { name: "El Morro", lat: 35.0378, lng: -108.3469, state: "New Mexico", visited: false },
  { name: "Fort Union", lat: 35.9250, lng: -105.0133, state: "New Mexico", visited: false },
  { name: "Gila Cliff Dwellings", lat: 33.2278, lng: -108.2706, state: "New Mexico", visited: false },
  { name: "Kasha-Katuwe Tent Rocks", lat: 35.6667, lng: -106.4167, state: "New Mexico", visited: false },
  { name: "Organ Mountains-Desert Peaks", lat: 32.3500, lng: -106.6000, state: "New Mexico", visited: false },
  { name: "Petroglyph", lat: 35.1650, lng: -106.7603, state: "New Mexico", visited: false },
  { name: "Prehistoric Trackways", lat: 32.3667, lng: -106.9000, state: "New Mexico", visited: false },
  { name: "Río Grande del Norte", lat: 36.7500, lng: -105.7500, state: "New Mexico", visited: false },
  { name: "Salinas Pueblo Missions", lat: 34.2597, lng: -106.0592, state: "New Mexico", visited: false },
  
  // Oregon
  { name: "Cascade-Siskiyou", lat: 42.0667, lng: -122.4500, state: "Oregon", visited: false },
  { name: "John Day Fossil Beds", lat: 44.5558, lng: -119.6450, state: "Oregon", visited: false },
  { name: "Newberry Volcanic", lat: 43.6889, lng: -121.2367, state: "Oregon", visited: false },
  { name: "Oregon Caves", lat: 42.0978, lng: -123.4072, state: "Oregon", visited: false },
  
  // Utah
  { name: "Bears Ears", lat: 37.6000, lng: -109.8333, state: "Utah", visited: false },
  { name: "Cedar Breaks", lat: 37.6222, lng: -112.8456, state: "Utah", visited: false },
  { name: "Dinosaur", lat: 40.4397, lng: -109.3000, state: "Utah", visited: true },
  { name: "Grand Staircase-Escalante", lat: 37.4667, lng: -111.7500, state: "Utah", visited: false },
  { name: "Hovenweep", lat: 37.3833, lng: -109.0783, state: "Utah", visited: false },
  { name: "Natural Bridges", lat: 37.6100, lng: -110.0069, state: "Utah", visited: false },
  { name: "Rainbow Bridge", lat: 37.0778, lng: -110.9625, state: "Utah", visited: false },
  { name: "Timpanogos Cave", lat: 40.4428, lng: -111.7094, state: "Utah", visited: false },
  
  // Washington
  { name: "Hanford Reach", lat: 46.6333, lng: -119.5333, state: "Washington", visited: false },
  { name: "Mount St. Helens", lat: 46.1914, lng: -122.1956, state: "Washington", visited: true },
  { name: "San Juan Islands", lat: 48.5333, lng: -123.0333, state: "Washington", visited: false },
  
  // Wyoming
  { name: "Devils Tower", lat: 44.5902, lng: -104.7150, state: "Wyoming", visited: false },
  { name: "Fossil Butte", lat: 41.8583, lng: -110.7697, state: "Wyoming", visited: false },
  
  // Other States
  { name: "Agate Fossil Beds", lat: 42.4169, lng: -103.7272, state: "Nebraska", visited: false },
  { name: "Alibates Flint Quarries", lat: 35.5750, lng: -101.6889, state: "Texas", visited: false },
  { name: "Buck Island Reef", lat: 17.7881, lng: -64.6219, state: "US Virgin Islands", visited: false },
  { name: "Effigy Mounds", lat: 43.0864, lng: -91.1889, state: "Iowa", visited: false },
  { name: "Fort McHenry", lat: 39.2625, lng: -76.5797, state: "Maryland", visited: false },
  { name: "George Washington Birthplace", lat: 38.1861, lng: -76.9294, state: "Virginia", visited: false },
  { name: "Harriet Tubman Underground Railroad", lat: 38.4500, lng: -76.1333, state: "Maryland", visited: false },
  { name: "Jewel Cave", lat: 43.7306, lng: -103.8294, state: "South Dakota", visited: false },
  { name: "Mill Springs Battlefield", lat: 37.0833, lng: -84.7333, state: "Kentucky", visited: false },
  { name: "Ocmulgee Mounds", lat: 32.8392, lng: -83.6072, state: "Georgia", visited: false },
  { name: "Poverty Point", lat: 32.6381, lng: -91.4086, state: "Louisiana", visited: false },
  { name: "Pullman", lat: 41.6933, lng: -87.6094, state: "Illinois", visited: false },
  { name: "Russell Cave", lat: 34.9747, lng: -85.8094, state: "Alabama", visited: false },
  { name: "Statue of Liberty", lat: 40.6892, lng: -74.0445, state: "New York", visited: false },
  { name: "Stonewall", lat: 40.7339, lng: -74.0021, state: "New York", visited: false }
];

// Initialize the map when the page loads
document.addEventListener('DOMContentLoaded', function() {
  // Create the map centered on the continental US
  const map = L.map('national-parks-map', {
    center: [39.8283, -98.5795],
    zoom: 4,
    minZoom: 3,
    maxZoom: 18
  });

  // Define base layers
  const streetMap = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    maxZoom: 19
  });

  const satelliteMap = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
    attribution: 'Tiles &copy; Esri &mdash; Source: Esri, i-cubed, USDA, USGS, AEX, GeoEye, Getmapping, Aerogrid, IGN, IGP, UPR-EGP, and the GIS User Community',
    maxZoom: 19
  });

  const terrainMap = L.tileLayer('https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png', {
    attribution: 'Map data: &copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors, <a href="http://viewfinderpanoramas.org">SRTM</a> | Map style: &copy; <a href="https://opentopomap.org">OpenTopoMap</a> (<a href="https://creativecommons.org/licenses/by-sa/3.0/">CC-BY-SA</a>)',
    maxZoom: 17
  });

  // Add default layer (street map)
  streetMap.addTo(map);

  // Create overlay layers (can be toggled on/off)
  const streetOverlay = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    maxZoom: 19,
    opacity: 0.6
  });

  const satelliteOverlay = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
    attribution: 'Tiles &copy; Esri',
    maxZoom: 19,
    opacity: 0.6
  });

  const terrainOverlay = L.tileLayer('https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; <a href="https://opentopomap.org">OpenTopoMap</a>',
    maxZoom: 17,
    opacity: 0.6
  });

  // Create layer groups for parks and monuments (must be created before overlayMaps)
  const parksLayer = L.layerGroup();
  const monumentsLayer = L.layerGroup();
  
  // Add parks layer to map by default
  parksLayer.addTo(map);

  // Create layer control with base maps and overlays
  const baseMaps = {
    "Street Map": streetMap,
    "Satellite": satelliteMap,
    "Terrain": terrainMap
  };

  const overlayMaps = {
    "Street Overlay": streetOverlay,
    "Satellite Overlay": satelliteOverlay,
    "Terrain Overlay": terrainOverlay
  };

  const layerControl = L.control.layers(baseMaps, overlayMaps).addTo(map);

  // Add opacity slider and zoom warning to the layer control
  setTimeout(() => {
    const layerControlContainer = document.querySelector('.leaflet-control-layers');
    if (layerControlContainer) {
      const opacityDiv = document.createElement('div');
      opacityDiv.className = 'leaflet-control-layers-separator';
      opacityDiv.style.marginTop = '10px';
      
      const opacityControl = document.createElement('div');
      opacityControl.className = 'opacity-control-inline';
      opacityControl.innerHTML = `
        <div class="opacity-control-content">
          <label for="overlay-opacity">Overlay Opacity</label>
          <div class="slider-container">
            <input type="range" id="overlay-opacity" min="0" max="100" value="60" step="5">
            <span id="opacity-value">60%</span>
          </div>
        </div>
      `;
      
      const zoomWarning = document.createElement('div');
      zoomWarning.id = 'terrain-zoom-warning';
      zoomWarning.className = 'terrain-zoom-warning';
      zoomWarning.style.display = 'none';
      zoomWarning.innerHTML = `
        <div class="warning-content">
          ⚠️ Terrain layers unavailable at this zoom level (max: 17)
        </div>
      `;
      
      const layersList = layerControlContainer.querySelector('.leaflet-control-layers-list');
      if (layersList) {
        // Add Points of Interest section
        const poiSeparator = document.createElement('div');
        poiSeparator.className = 'leaflet-control-layers-separator';
        poiSeparator.style.marginTop = '10px';
        layersList.appendChild(poiSeparator);
        
        const poiSection = document.createElement('div');
        poiSection.className = 'poi-section';
        poiSection.innerHTML = `
          <div class="poi-section-header">Points of Interest</div>
          <label class="poi-checkbox-label">
            <input type="checkbox" id="parks-toggle" checked>
            <span>National Parks</span>
          </label>
          <label class="poi-checkbox-label">
            <input type="checkbox" id="monuments-toggle">
            <span>National Monuments</span>
          </label>
        `;
        layersList.appendChild(poiSection);
        
        // Handle parks toggle
        const parksToggle = document.getElementById('parks-toggle');
        if (parksToggle) {
          parksToggle.addEventListener('change', function() {
            if (this.checked) {
              map.addLayer(parksLayer);
            } else {
              map.removeLayer(parksLayer);
            }
          });
        }
        
        // Handle monuments toggle
        const monumentsToggle = document.getElementById('monuments-toggle');
        if (monumentsToggle) {
          monumentsToggle.addEventListener('change', function() {
            if (this.checked) {
              map.addLayer(monumentsLayer);
            } else {
              map.removeLayer(monumentsLayer);
            }
          });
        }
        
        layersList.appendChild(opacityDiv);
        layersList.appendChild(opacityControl);
        layersList.appendChild(zoomWarning);
      }
      
      // Handle opacity slider changes
      const slider = document.getElementById('overlay-opacity');
      const valueDisplay = document.getElementById('opacity-value');
      
      if (slider && valueDisplay) {
        slider.addEventListener('input', function() {
          const opacity = this.value / 100;
          valueDisplay.textContent = this.value + '%';
          
          // Apply opacity to any active overlay
          if (map.hasLayer(streetOverlay)) {
            streetOverlay.setOpacity(opacity);
          }
          if (map.hasLayer(satelliteOverlay)) {
            satelliteOverlay.setOpacity(opacity);
          }
          if (map.hasLayer(terrainOverlay)) {
            terrainOverlay.setOpacity(opacity);
          }
        });
      }
      
      // Handle terrain layer zoom limitations
      function updateTerrainAvailability() {
        const currentZoom = map.getZoom();
        const terrainMaxZoom = 17;
        const warning = document.getElementById('terrain-zoom-warning');
        
        if (currentZoom > terrainMaxZoom) {
          // Show warning
          if (warning) {
            warning.style.display = 'block';
          }
          
          // Remove terrain layers if active
          if (map.hasLayer(terrainMap)) {
            map.removeLayer(terrainMap);
            // Switch to satellite if no other base layer is active
            if (!map.hasLayer(streetMap) && !map.hasLayer(satelliteMap)) {
              map.addLayer(satelliteMap);
            }
          }
          if (map.hasLayer(terrainOverlay)) {
            map.removeLayer(terrainOverlay);
          }
        } else {
          // Hide warning
          if (warning) {
            warning.style.display = 'none';
          }
        }
      }
      
      // Check zoom level on map zoom
      map.on('zoomend', updateTerrainAvailability);
      
      // Initial check
      updateTerrainAvailability();
    }
  }, 100);

  // Custom icons for visited and unvisited parks
  const visitedIcon = L.divIcon({
    className: 'custom-park-marker visited',
    html: '<div class="marker-pin visited-pin"><span class="checkmark">✓</span></div>',
    iconSize: [30, 42],
    iconAnchor: [15, 42],
    popupAnchor: [0, -42]
  });

  const unvisitedIcon = L.divIcon({
    className: 'custom-park-marker unvisited',
    html: '<div class="marker-pin unvisited-pin"></div>',
    iconSize: [30, 42],
    iconAnchor: [15, 42],
    popupAnchor: [0, -42]
  });

  // Custom icons for monuments (smaller and different color)
  const visitedMonumentIcon = L.divIcon({
    className: 'custom-monument-marker visited',
    html: '<div class="marker-pin visited-monument-pin"><span class="checkmark">✓</span></div>',
    iconSize: [24, 34],
    iconAnchor: [12, 34],
    popupAnchor: [0, -34]
  });

  const unvisitedMonumentIcon = L.divIcon({
    className: 'custom-monument-marker unvisited',
    html: '<div class="marker-pin unvisited-monument-pin"></div>',
    iconSize: [24, 34],
    iconAnchor: [12, 34],
    popupAnchor: [0, -34]
  });

  // Add markers for each national park
  nationalParks.forEach(park => {
    const icon = park.visited ? visitedIcon : unvisitedIcon;
    const marker = L.marker([park.lat, park.lng], { icon: icon });
    
    // Add popup with park information
    const popupContent = `
      <div class="park-popup">
        <h3>${park.name}</h3>
        <p><strong>${park.state}</strong></p>
        <p class="park-type">National Park</p>
        ${park.visited ? '<p class="visited-badge">✓ Visited</p>' : ''}
      </div>
    `;
    marker.bindPopup(popupContent);
    marker.addTo(parksLayer);
  });

  // Add markers for each national monument
  nationalMonuments.forEach(monument => {
    const icon = monument.visited ? visitedMonumentIcon : unvisitedMonumentIcon;
    const marker = L.marker([monument.lat, monument.lng], { icon: icon });
    
    // Add popup with monument information
    const popupContent = `
      <div class="park-popup monument-popup">
        <h3>${monument.name}</h3>
        <p><strong>${monument.state}</strong></p>
        <p class="park-type">National Monument</p>
        ${monument.visited ? '<p class="visited-badge">✓ Visited</p>' : ''}
      </div>
    `;
    marker.bindPopup(popupContent);
    marker.addTo(monumentsLayer);
  });

  // Add custom CSS for markers
  const style = document.createElement('style');
  style.textContent = `
    .custom-park-marker {
      background: none;
      border: none;
    }
    
    .marker-pin {
      width: 24px;
      height: 24px;
      border-radius: 50% 50% 50% 0;
      position: absolute;
      transform: rotate(-45deg);
      left: 50%;
      top: 50%;
      margin: -30px 0 0 -15px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    
    .marker-pin::after {
      content: '';
      width: 16px;
      height: 16px;
      margin: 4px 0 0 4px;
      background: #fff;
      position: absolute;
      border-radius: 50%;
    }
    
    .visited-pin {
      background: #2ecc71;
      border: 2px solid #27ae60;
    }
    
    .unvisited-pin {
      background: #95a5a6;
      border: 2px solid #7f8c8d;
    }
    
    .checkmark {
      position: absolute;
      color: #fff;
      font-weight: bold;
      font-size: 16px;
      z-index: 1;
      transform: rotate(45deg);
      margin: -2px 0 0 -1px;
    }
    
    /* Monument marker styles - smaller and different colors */
    .custom-monument-marker {
      background: none;
      border: none;
    }
    
    .custom-monument-marker .marker-pin {
      width: 20px;
      height: 20px;
    }
    
    .custom-monument-marker .marker-pin::after {
      width: 14px;
      height: 14px;
      margin: 3px 0 0 3px;
    }
    
    .visited-monument-pin {
      background: #3498db;
      border: 2px solid #2980b9;
    }
    
    .unvisited-monument-pin {
      background: #bdc3c7;
      border: 2px solid #95a5a6;
    }
    
    .custom-monument-marker .checkmark {
      font-size: 13px;
      margin: -2px 0 0 0px;
    }
    
    .park-popup h3 {
      margin: 0 0 8px 0;
      color: #2c3e50;
      font-size: 16px;
    }
    
    .park-popup p {
      margin: 4px 0;
      color: #555;
      font-size: 14px;
    }
    
    .park-type {
      font-size: 12px;
      color: #7f8c8d;
      font-style: italic;
      margin-top: 2px;
    }
    
    .visited-badge {
      color: #2ecc71;
      font-weight: bold;
      margin-top: 8px;
    }
    
    #national-parks-map {
      border: 2px solid #e0e0e0;
    }
    
    /* Opacity control styling - inline within layer control */
    .opacity-control-inline {
      padding: 8px 10px 10px 10px;
    }
    
    .opacity-control-content {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    
    .opacity-control-content label {
      font-size: 12px;
      font-weight: bold;
      color: #333;
      margin: 0;
    }
    
    .opacity-control-content .slider-container {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .opacity-control-content input[type="range"] {
      flex: 1;
      min-width: 100px;
      margin: 0;
      cursor: pointer;
      -webkit-appearance: none;
      appearance: none;
      height: 6px;
      background: #ddd;
      border-radius: 3px;
      outline: none;
    }
    
    .opacity-control-content #opacity-value {
      font-size: 11px;
      color: #666;
      font-weight: bold;
      min-width: 35px;
      text-align: right;
    }
    
    /* Custom range slider styling */
    .opacity-control-content input[type="range"]::-webkit-slider-thumb {
      -webkit-appearance: none;
      appearance: none;
      width: 14px;
      height: 14px;
      background: #2ecc71;
      border-radius: 50%;
      cursor: pointer;
      transition: background 0.2s;
    }
    
    .opacity-control-content input[type="range"]::-webkit-slider-thumb:hover {
      background: #27ae60;
    }
    
    .opacity-control-content input[type="range"]::-moz-range-thumb {
      width: 14px;
      height: 14px;
      background: #2ecc71;
      border-radius: 50%;
      cursor: pointer;
      border: none;
      transition: background 0.2s;
    }
    
    .opacity-control-content input[type="range"]::-moz-range-thumb:hover {
      background: #27ae60;
    }
    
    /* Adjust layer control width for better slider fit */
    .leaflet-control-layers-expanded {
      min-width: 200px;
    }
    
    /* Terrain zoom warning styling */
    .terrain-zoom-warning {
      padding: 8px 10px;
      margin-top: 5px;
      border-top: 1px solid #ddd;
    }
    
    .terrain-zoom-warning .warning-content {
      font-size: 11px;
      color: #e67e22;
      background: #fef5e7;
      padding: 6px 8px;
      border-radius: 3px;
      border-left: 3px solid #e67e22;
      line-height: 1.4;
    }
    
    /* Points of Interest section styling */
    .poi-section {
      padding: 8px 10px;
    }
    
    .poi-section-header {
      font-size: 12px;
      font-weight: bold;
      color: #333;
      margin-bottom: 8px;
      padding-bottom: 4px;
      border-bottom: 1px solid #ddd;
    }
    
    .poi-checkbox-label {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 4px 0;
      cursor: pointer;
      font-size: 13px;
      color: #333;
    }
    
    .poi-checkbox-label:hover {
      background: #f5f5f5;
      padding-left: 4px;
      margin-left: -4px;
      border-radius: 3px;
    }
    
    .poi-checkbox-label input[type="checkbox"] {
      cursor: pointer;
      width: 16px;
      height: 16px;
    }
    
    .poi-checkbox-label span {
      flex: 1;
    }
  `;
  document.head.appendChild(style);
});
