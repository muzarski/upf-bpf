#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdint.h>
#include <string>
#include <vector>
#include <map>
#include <types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class Util
{
public:
  virtual ~Util();
  static std::vector<u_char> stringToMac(std::string const &s);
  static void getFlowDirection(std::string direction);
  static struct in_addr convertIpToInet(std::string ipAddress);
  static struct in6_addr convertIp6ToInet(std::string ipAddress);
  static struct sockaddr_storage convertIpToSockaddr(const std::string& ipAddress);
  static struct ipKey {
    uint32_t ip[4];
    uint8_t is_v6;
  };
  static struct ipKey convertIpToIpKey(const std::string &ipAddress);
private:
};

#endif // __UTIL_H__
