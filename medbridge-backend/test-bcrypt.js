const bcrypt = require("bcryptjs");

bcrypt.compare(
  "admin123",
  "$2b$10$VRjnuSsS51VcMmB5Ucu8EOERXngBbfFWImUSg5s3M3kAmuMmZKdH2"
).then(result => {
  console.log("Match result:", result);
});