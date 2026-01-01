const geoip = require("geoip-lite");
const { redis } = require("../config/redis");

// Calculate distance between two coordinates (Haversine formula)
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // Earth's radius in km
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

function toRad(deg) {
  return deg * (Math.PI / 180);
}

// Calculate maximum possible travel time (assuming airplane speed)
function getMinTravelTime(distanceKm) {
  const avgFlightSpeed = 900; // km/h (commercial jet)
  return (distanceKm / avgFlightSpeed) * 3600 * 1000; // Convert to milliseconds
}

async function checkGeoImpossibility(userId, ipAddress) {
  const geo = geoip.lookup(ipAddress);
  
  if (!geo) {
    return {
      isImpossible: false,
      reason: "Could not determine location",
      riskScore: 0
    };
  }

  const currentLocation = {
    country: geo.country,
    city: geo.city,
    lat: geo.ll[0],
    lon: geo.ll[1],
    timestamp: Date.now()
  };

  // Get last known location from Redis
  const lastLocationKey = `user:${userId}:last_location`;
  const lastLocationData = await redis.get(lastLocationKey);

  if (!lastLocationData) {
    // First login or no previous data
    await redis.setex(
      lastLocationKey,
      86400 * 7, // 7 days
      JSON.stringify(currentLocation)
    );
    
    return {
      isImpossible: false,
      reason: "First location recorded",
      riskScore: 0,
      currentLocation
    };
  }

  const lastLocation = JSON.parse(lastLocationData);
  
  // Calculate distance and time difference
  const distance = calculateDistance(
    lastLocation.lat,
    lastLocation.lon,
    currentLocation.lat,
    currentLocation.lon
  );
  
  const timeDiff = currentLocation.timestamp - lastLocation.timestamp;
  const minTravelTime = getMinTravelTime(distance);

  // Check if travel is physically impossible
  const isImpossible = timeDiff < minTravelTime && distance > 500; // 500km threshold
  
  let riskScore = 0;
  let reason = "";

  if (isImpossible) {
    riskScore = 95;
    reason = `Impossible travel: ${distance.toFixed(0)}km in ${(timeDiff / 60000).toFixed(0)} minutes`;
  } else if (distance > 3000 && timeDiff < 3600000) { // 3000km in 1 hour
    riskScore = 75;
    reason = `Suspicious: Long distance travel in short time`;
  } else if (lastLocation.country !== currentLocation.country) {
    riskScore = 40;
    reason = `Country changed: ${lastLocation.country} → ${currentLocation.country}`;
  } else if (distance > 100) {
    riskScore = 20;
    reason = `Location changed by ${distance.toFixed(0)}km`;
  }

  // Update last location
  await redis.setex(
    lastLocationKey,
    86400 * 7,
    JSON.stringify(currentLocation)
  );

  return {
    isImpossible,
    reason,
    riskScore,
    currentLocation,
    lastLocation,
    distance: distance.toFixed(2),
    timeDiff: (timeDiff / 60000).toFixed(0) // minutes
  };
}

// Store location history for analytics
async function storeLocationHistory(userId, ipAddress, deviceId) {
  const geo = geoip.lookup(ipAddress);
  if (!geo) return;

  const historyKey = `user:${userId}:location_history`;
  const locationData = {
    deviceId,
    country: geo.country,
    city: geo.city,
    ip: ipAddress,
    timestamp: Date.now()
  };

  // Keep last 50 locations
  await redis.lpush(historyKey, JSON.stringify(locationData));
  await redis.ltrim(historyKey, 0, 49);
  await redis.expire(historyKey, 86400 * 30); // 30 days
}

module.exports = {
  checkGeoImpossibility,
  storeLocationHistory,
  calculateDistance
};