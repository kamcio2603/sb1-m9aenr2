import nacl from 'tweetnacl';
import util from 'tweetnacl-util';

function isValidIPv4(ip) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(ip)) return false;
  return ip.split('.').every(octet => parseInt(octet) >= 0 && parseInt(octet) <= 255);
}

function isValidSubnet(subnet) {
  const [ip, mask] = subnet.split('/');
  if (!isValidIPv4(ip)) return false;
  const maskNum = parseInt(mask);
  return maskNum >= 0 && maskNum <= 32;
}

function generateKeyPair() {
  const keyPair = nacl.box.keyPair();
  return {
    publicKey: util.encodeBase64(keyPair.publicKey),
    privateKey: util.encodeBase64(keyPair.secretKey)
  };
}

function generateConfig(name, publicKey, privateKey, address, peerName, peerPublicKey, peerAddress, listenPort, peerEndpoint, allowedIPs, sourceAllowedIPs, persistentKeepalive, isMaster) {
  let config = '';

  if (isMaster) {
    config += `/interface/wireguard\nadd listen-port=${listenPort} name=${name} private-key="${privateKey}"\n\n`;
    config += `/interface/wireguard/peers\nadd allowed-address=${allowedIPs} endpoint-address=${peerEndpoint} endpoint-port=${listenPort} interface=${name} public-key="${peerPublicKey}"\n\n`;
    config += `/ip/address\nadd address=${address}/24 interface=${name}\n\n`;
    config += `/ip/route\nadd comment="WireGuard" distance=1 dst-address=${allowedIPs} gateway=${name}\n`;
  } else {
    config += `/interface/wireguard\nadd name=${name} private-key="${privateKey}"\n\n`;
    config += `/interface/wireguard/peers\nadd allowed-address=${sourceAllowedIPs} endpoint-address=${peerEndpoint} endpoint-port=${listenPort} interface=${name} persistent-keepalive=${persistentKeepalive}s public-key="${peerPublicKey}"\n\n`;
    config += `/ip/address\nadd address=${address}/24 interface=${name}\n\n`;
    config += `/ip/route\nadd comment="WireGuard" distance=1 dst-address=${sourceAllowedIPs} gateway=${name}\n`;
  }

  return config;
}
document.getElementById('configForm').addEventListener('submit', function (e) {
  e.preventDefault();

  const routerMasterName = document.getElementById('routerMasterName').value;
  const routerMasterIP = document.getElementById('routerMasterIP').value;
  const routerMasterFQDN = document.getElementById('routerMasterFQDN').value;
  const routerMasterSubnet = document.getElementById('routerMasterSubnet').value;
  const routerClientName = document.getElementById('routerClientName').value;
  const routerClientIP = document.getElementById('routerClientIP').value;
  const clientLANSubnet = document.getElementById('clientLANSubnet').value;
  const listenPort = document.getElementById('listenPort').value;
  const keepalive = document.getElementById('keepalive').value;

  const errorMessages = [];
  // Walidacja adresów IP i podsieci
  if (!isValidIPv4(routerMasterIP)) {
    errorMessages.push('Nieprawidłowy adres IP routera Master');
  }
  if (!isValidIPv4(routerClientIP)) {
    errorMessages.push('Nieprawidłowy adres IP routera Client');
  }
  if (!isValidSubnet(routerMasterSubnet)) {
    errorMessages.push('Nieprawidłowa podsieć LAN routera Master');
  }
  if (!isValidSubnet(clientLANSubnet)) {
    errorMessages.push('Nieprawidłowa podsieć LAN klienta');
  }

  const errorMessagesElement = document.getElementById('errorMessages');

  if (errorMessages.length > 0) {
    errorMessagesElement.innerHTML = errorMessages.map(msg => `<p>${msg}</p>`).join('');
    errorMessagesElement.classList.add('show');
    return;
  } else {
    errorMessagesElement.innerHTML = '';
    errorMessagesElement.classList.remove('show');
  }

  // Generowanie kluczy
  const masterKeys = generateKeyPair();
  const clientKeys = generateKeyPair();

  const configMaster = generateConfig(
    routerMasterName,
    masterKeys.publicKey,
    masterKeys.privateKey,
    routerMasterIP,
    routerClientName,
    clientKeys.publicKey,
    routerClientIP,
    listenPort,
    routerMasterFQDN,
    clientLANSubnet,
    routerMasterSubnet,
    keepalive,
    true
  );
  const configClient = generateConfig(
    routerClientName,
    clientKeys.publicKey,
    clientKeys.privateKey,
    routerClientIP,
    routerMasterName,
    masterKeys.publicKey,
    routerMasterIP,
    listenPort,
    routerMasterFQDN,
    clientLANSubnet,
    routerMasterSubnet,
    keepalive,
    false
  );

  document.getElementById('configMaster').textContent = configMaster;
  document.getElementById('configClient').textContent = configClient;
  document.getElementById('output').classList.remove('hidden');
});