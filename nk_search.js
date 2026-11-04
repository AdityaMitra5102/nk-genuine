const lookupMap = new Map([
  ["ad8fd1d16f59104b9e06ef323cc03f777ed5303cd421a101c9cb00bb3fdf722d", "Nitrokey 3"],
  
  ["aa1cb760c2879530e7d7fed3da75345d25774be9cfdbbcbd36fdee767025f34b", "Nitrokey 3 NFC"],
  ["4c331d7af869fd1d8217198b917a33d1fa503e9778da7638504a64a438661ae0", "Nitrokey 3A Mini"],
  ["f1ed1aba24b16e8e3fabcda72b10cbfa54488d3b778bda552162d60c6dd7b4fa", "Nitrokey 3A Mini Test"],
  
  ["c7512dfcd15ffc5a7b4000e4898e5956ee858027794c5086cc137a02cd15d123", "Nitrokey Passkey"],
  
]);

const TEST_KEYS = new Set(["c7d87cac86b69059bbff5c43872a20892267518614dfc9822c7ee55ad89f0022"]);

function lookup(key) {
  if (TEST_KEYS.has(key)) {
    return ["Test", "Nitrokey Hacker"];
  }

  if (lookupMap.has(key)) {
    return ["Verified", lookupMap.get(key)];
  }

  return ["Failed", "Unexpected Certificate"];
}

