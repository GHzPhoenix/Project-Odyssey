const bcrypt = require('bcrypt');

async function generateHashes() {
  const userHash = await bcrypt.hash('password123', 10);
  const adminHash = await bcrypt.hash('adminsecure', 10);
  console.log('User hash:', userHash);
  console.log('Admin hash:', adminHash);
}

generateHashes();
