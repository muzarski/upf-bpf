#include "Util.h"
#include <algorithm>
#include <cstdint>
#include <stdlib.h>
#include "LogDefines.h"
#include <sstream>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


Util::~Util() { LOG_FUNC(); }

// C - https://stackoverflow.com/a/7326381/2203249
// C++ - https://stackoverflow.com/a/34949247/2203249
std::vector<u_char> Util::stringToMac(std::string const &s)
{
  std::vector<u_char> macAddress(6);
  u_char *a = macAddress.data();
  std::stringstream ss;
  int last = -1;
  int rc = sscanf(s.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%n", a + 0, a + 1, a + 2, a + 3, a + 4, a + 5, &last);
  for (auto i: macAddress){
    std::cout << "mac address: " << std::hex << i << std::endl;
  }
  LOG_DBG("mac address: {}", ss.str());
  if(rc != 6 || s.size() != last)
    throw std::runtime_error("invalid mac address format " + s);
  return macAddress;
}

struct in_addr Util::convertIpToInet(std::string ipAddress){
  struct in_addr inetIpAddress;
  if(inet_aton(ipAddress.c_str(), &inetIpAddress) == 0) {
    fprintf(stderr, "Invalid address\n");
    throw std::runtime_error("Invalid address");
  }
  return inetIpAddress;
}

struct in6_addr Util::convertIp6ToInet(std::string ipAddress) {
  struct in6_addr inetIp6Address;
  if (inet_pton(AF_INET6, ipAddress.c_str(), &inetIp6Address) == 0) {
    fprintf(stderr, "Invalid Ipv6 address\n");
    throw std::runtime_error("Invalid Ipv6 address");
  }
  
  return inetIp6Address;
}


struct sockaddr_storage Util::convertIpToSockaddr(const std::string& ipAddress) {
  struct addrinfo *info;
  struct sockaddr_storage res{};
  
  if (getaddrinfo(ipAddress.c_str(), nullptr, nullptr, &info) != 0) {
    fprintf(stderr, "Invalid ip address\n");
    throw std::runtime_error("Invalid ip address (getaddrinfo)\n");
  }
  
  if (info->ai_family != AF_INET && info->ai_family != AF_INET6) {
    fprintf(stderr, "Address is neither v4 nor v6.\n");
    throw std::runtime_error("Address is neither v4 nor v6.\n");
  }
  
  std::memcpy(&res, info->ai_addr, info->ai_addrlen);
  
  return res;
}

struct Util::ipKey Util::convertIpToIpKey(const std::string &ipAddress) {
  struct ipKey key{};
  std::memset(&key, 0, sizeof(key));
  
  struct addrinfo *info;
  
  if (getaddrinfo(ipAddress.c_str(), nullptr, nullptr, &info) != 0) {
    fprintf(stderr, "Invalid ip address\n");
    throw std::runtime_error("Invalid ip address (getaddrinfo)\n");
  }
  
  if (info->ai_family != AF_INET && info->ai_family != AF_INET6) {
    fprintf(stderr, "Address is neither v4 nor v6.\n");
    throw std::runtime_error("Address is neither v4 nor v6.\n");
  }
  
  key.is_v6 = info->ai_family == AF_INET6;
  if (info->ai_family == AF_INET) {
    struct in_addr *ipv4 = &((struct sockaddr_in*) info->ai_addr)->sin_addr;
    std::memcpy(&key.ip, ipv4, sizeof(struct in_addr));
  }
  else {
    struct in6_addr *ipv6 = &((struct sockaddr_in6*) info->ai_addr)->sin6_addr;
    std::memcpy(&key.ip, ipv6, sizeof(struct in6_addr));
  }
  
  return key;
}
