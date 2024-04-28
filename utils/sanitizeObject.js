// Define a function to sanitize an object by including only specified keys
const sanitizeObject = (object, ...keys) => {
  // Convert the object into an array of key-value pairs, then filter out
  // the entries that are not in the specified keys
  const sanitizedEntries = Object.entries(object)
      .filter(([key]) => keys.includes(key));

  // Convert the filtered key-value pairs back into an object
  return Object.fromEntries(sanitizedEntries);
};

// Export the sanitizeObject function to make it available for other modules
module.exports = sanitizeObject;

