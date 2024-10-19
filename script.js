import * as nacl from 'tweetnacl';
import * as util from 'tweetnacl-util';

function generateKeyPair() {
  const keyPair = nacl.box.keyPair();
  return {
    publicKey: util.encodeBase64(keyPair.publicKey),
    privateKey: util.encodeBase64(keyPair.secretKey),
  };
}

function isValidIPv4(ip) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(ip)) return false;
  const octets = ip.split('.');
  return octets.every(octet => parseInt(octet) >= 0 && parseInt(octet) <= 255);
}

function isValidSubnet(subnet) {
  const [ip, mask] = subnet.split('/');
  if (!isValidIPv4(ip)) return false;
  const maskNum = parseInt(mask);
  return !isNaN(maskNum) && maskNum >= 0 && maskNum <= 32;
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

  // Walidacja adresów IP i podsieci
  if (!isValidIPv4(routerMasterIP)) {
    alert('Nieprawidłowy adres IP routera Master');
    return;
  }
  if (!isValidIPv4(routerClientIP)) {
    alert('Nieprawidłowy adres IP routera Client');
    return;
  }
  if (!isValidSubnet(routerMasterSubnet)) {
    alert('Nieprawidłowa podsieć LAN routera Master');
    return;
  }
  if (!isValidSubnet(clientLANSubnet)) {
    alert('Nieprawidłowa podsieć LAN klienta');
    return;
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

function generateConfig(
  localName,
  localPublicKey,
  localPrivateKey,
  localIP,
  remoteName,
  remotePublicKey,
  remoteIP,
  listenPort,
  remoteFQDN,
  clientLANSubnet,
  masterLANSubnet,
  keepalive,
  isMaster
) {
  const isClient = !isMaster;
  const endpointAddress = isClient ? remoteFQDN : remoteIP;

  let config = `# Konfiguracja WireGuard dla ${localName}
/interface wireguard add listen-port=${listenPort} mtu=1420 name=${localName} private-key="${localPrivateKey}"
`;

  if (isMaster) {
    config += `/interface wireguard peers add allowed-address=0.0.0.0/0 interface=${localName} public-key="${remotePublicKey}" name="${localName}"
`;
  } else {
    config += `/interface wireguard peers add allowed-address=0.0.0.0/0 endpoint-address=${endpointAddress} endpoint-port=${listenPort} interface=${localName} public-key="${remotePublicKey}" persistent-keepalive=${keepalive}s name="${localName}"
`;
  }

  config += `/ip address add address=${localIP}/30 interface=${localName}
`;

  if (isMaster) {
    config += `
# Routing do sieci LAN klienta
/ip route add dst-address=${clientLANSubnet} gateway=${remoteIP}
`;
  } else {
    config += `
# Routing do sieci LAN mastera
/ip route add dst-address=${masterLANSubnet} gateway=${remoteIP}
`;
  }

  return config;
}