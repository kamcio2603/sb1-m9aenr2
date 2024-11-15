import nacl from 'tweetnacl';
import util from 'tweetnacl-util';

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

function showErrors(errors) {
  const errorDiv = document.getElementById('errorMessages');
  errorDiv.innerHTML = ''; // Wyczyść poprzednie błędy
  
  // Usuń poprzednie podświetlenia
  document.querySelectorAll('input').forEach(input => {
    input.classList.remove('invalid');
  });
  
  if (errors.length > 0) {
    const errorList = document.createElement('ul');
    errorList.className = 'error-list';
    
    errors.forEach(({ message, inputId }) => {
      // Dodaj błąd do listy
      const errorItem = document.createElement('li');
      errorItem.textContent = message;
      errorList.appendChild(errorItem);
      
      // Podświetl pole z błędem
      const inputElement = document.getElementById(inputId);
      if (inputElement) {
        inputElement.classList.add('invalid');
      }
    });
    
    errorDiv.appendChild(errorList);
    errorDiv.classList.add('show');
    
    // Automatycznie ukryj błędy po 5 sekundach
    setTimeout(() => {
      errorDiv.classList.remove('show');
      document.querySelectorAll('input').forEach(input => {
        input.classList.remove('invalid');
      });
    }, 5000);
  }
}

// Usuń klasę invalid przy wprowadzaniu nowej wartości
document.querySelectorAll('input').forEach(input => {
  input.addEventListener('input', () => {
    input.classList.remove('invalid');
    // Jeśli nie ma już żadnych pól z błędami, ukryj komunikaty
    if (!document.querySelector('input.invalid')) {
      document.getElementById('errorMessages').classList.remove('show');
    }
  });
});

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

  // Zbierz wszystkie błędy
  const errors = [];

  if (!isValidIPv4(routerMasterIP)) {
    errors.push({
      message: 'Nieprawidłowy adres IP routera Master',
      inputId: 'routerMasterIP'
    });
  }
  if (!isValidIPv4(routerClientIP)) {
    errors.push({
      message: 'Nieprawidłowy adres IP routera Client',
      inputId: 'routerClientIP'
    });
  }
  if (!isValidSubnet(routerMasterSubnet)) {
    errors.push({
      message: 'Nieprawidłowa podsieć LAN routera Master',
      inputId: 'routerMasterSubnet'
    });
  }
  if (!isValidSubnet(clientLANSubnet)) {
    errors.push({
      message: 'Nieprawidłowa podsieć LAN klienta',
      inputId: 'clientLANSubnet'
    });
  }

  // Jeśli są błędy, pokaż je i przerwij
  if (errors.length > 0) {
    showErrors(errors);
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

# Konfiguracja firewalla dla interfejsu WireGuard
# Zezwól na ruch przychodzący na interfejsie WireGuard (np. ping, zarządzanie)
/ip firewall filter add chain=input action=accept in-interface=${localName} place-before=1 \\
    comment="Zezwól na ruch przychodzący przez tunel WireGuard (ping, zarządzanie)"

# Zezwól na przekazywanie ruchu z interfejsu WireGuard do sieci LAN
/ip firewall filter add chain=forward action=accept in-interface=${localName} \\
    comment="Zezwól na przekazywanie ruchu z tunelu WireGuard do sieci LAN"
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