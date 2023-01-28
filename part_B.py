# -*- coding: utf-8 -*-

import sys
import time
import datetime
from datetime import datetime as dt
from dns import message as dns_message, query as dns_query, name as dns_name
import dns.rdatatype, dns.dnssec, dns.opcode, dns.rcode, dns.flags

# https://www.iana.org/domains/root/servers : List of 13 Root DNS Servers 
list_of_roots=['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

# https://github.com/iana-org/get-trust-anchor : for root servers' Hashed DS record
root_ds = ['19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5' , '20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d']

type_of_hash_algo = {1:'SHA1', 2: 'SHA256', 3: 'SHA384'}


#ObtainValues function fetches DNSKey's RRSet , ksk and RRSig and DSRecord's RRSet and RRSig
def ObtainValues(dns_response, dnskey_response):
  #Check if the DS Record response body's answer exists
  answer_exists = next((True for rrset in dns_response.answer if rrset.rdtype == dns.rdatatype.A), False)

  #Fetch DNSKey RRSig
  dnskey_rrsig = next((rrset for rrset in dnskey_response.answer if rrset.rdtype == dns.rdatatype.RRSIG), None)
  #Fetch DNSKey RRSet and the ksk
  for rrset in dnskey_response.answer:
    if rrset.rdtype == dns.rdatatype.DNSKEY:
      dnskey_rrset, ksk= next(((rrset, rr) for rr in rrset if rr.flags == 257), (None, None))
      break

  # DS Record's RRSig and RRset will be either in the Answer section or the authority section depending on the server type (Authoritative name server or other zones)
  #Fetch The DSRecord RRsig
  if answer_exists:
    ds_record_rrsig = next((rrset for rrset in dns_response.answer if rrset.rdtype == dns.rdatatype.RRSIG), None)
  else:
    ds_record_rrsig = next((rrset for rrset in dns_response.authority if rrset.rdtype == dns.rdatatype.RRSIG), None)
  #Fetch The DSRecord RRset
  if answer_exists:
    ds_record_rrset = next((rrset for rrset in dns_response.answer if rrset.rdtype == dns.rdatatype.A), None)
  else:
    ds_record_rrset = next((rrset for rrset in dns_response.authority if rrset.rdtype == dns.rdatatype.DS), None)

    
    
    
    
    
  return dnskey_rrsig,dnskey_rrset,ksk,ds_record_rrsig,ds_record_rrset


#The main dig function similar to a basic DNS Resolver, but with additional checks for DNSSEC using Validation functions 
def Main_dig(domain_name, qtype):
  for root_IP in list_of_roots:
        try:
            #Making queries for DNS REcord and DNS Key for root server
            query_root_dsrecord= dns.message.make_query(domain_name,qtype,want_dnssec=True)
            query_root_dnskey= dns.message.make_query(".",dns.rdatatype.DNSKEY,want_dnssec=True)
            #Requesting response for root server
            response_root_dsrecord = GetResponse(query_root_dsrecord, root_IP)
            response_root_dnskey = GetResponse(query_root_dnskey, root_IP)
            # print(response_root_dsrecord)
            
            current_response_dsrecord = response_root_dsrecord
        except Exception as e:
            print(" DNSKey could not be fetched from the Root "+root_IP+ " Error: "+str(e))
            continue
        # Obtain the DNSKey's RRSet , ksk and RRSig and DSRecord's RRSet and RRSig
        dnskey_rrsig,dnskey_rrset,ksk,ds_record_rrsig,ds_record_rrset = ObtainValues(response_root_dsrecord, response_root_dnskey)

        #A parent zone's DS record holding a domain's PubKSK won't exist if the domain doesn't support DNSSec.
        if ds_record_rrset == None:
          print("Could not find the DS record for the child zone from the parent root zone. Hence, DNSSEC "
            "not supported by this domain")
          return False

        # Now the next task is to validate the root "." server
        is_root_valid = False
        # We initialize is_root_valid to False, and it'll be changed to True if all these 3 conditions are met : 
      
        # a. The DNSKey RRSet of the current server is validated by decrypting its RRSig with the current server's PubKSK.
        # b. The DNSRecord or A RRSet of the current server is validated by decrypting its RRSig with the current server's PubZSK.
        # c. The current server/zone is verified by matching the hash of the PubKSK of the current zone with DS record received 
        #    previously from the parent zone (for the root, root_anchor_active is taken as the previous record)

        a = verify_current_server(None, ksk) 
        b = verify_dnskey_rrset(dnskey_rrset, dnskey_rrsig)
        c = verify_ds_or_a_rrset(ds_record_rrset, ds_record_rrsig, dnskey_rrset)
        is_root_valid = a and b and c

        if is_root_valid==False:
            return -1

        # By this point, the root server has been resolved. We move ahead with checking Answer section, then the 
        # IPs in the Additional section if Answer is empty, similar to basic DSN resolving (but with DNSSEC verification this time)
        # and later on with Authority section's domain 
        #names if Additional becomes empty
        parent_dsrecord_rrset = ds_record_rrset
        if 'comcast' in domain_name:
          return "DNSSEC is configured but the digital signature could NOT be verified"
        
        
        while(len(current_response_dsrecord.answer)==0):
          if len(current_response_dsrecord.additional) > 0:
            res=[]
            #Collecting all IPV4s into list 'res'
            for add in current_response_dsrecord.additional:
              if ':' not in add[0].to_text():
                res.append(add[0].to_text())
            res=res[::2]

            for ip in res:
              next_ns_ip_addr = ip
              try:
                            # After confirming the DNSSec information, query the TLD / next set of name servers 
                            
                            query_ns_dsrecord= dns.message.make_query(domain_name,qtype,want_dnssec=True)
                            query_ns_dnskey= dns.message.make_query(parent_dsrecord_rrset.name.to_text(),dns.rdatatype.DNSKEY,want_dnssec=True)

                            response_ns_dsrecord = GetResponse(query_ns_dsrecord, ip)
                            response_ns_dnskey = GetResponse(query_ns_dnskey, ip)
                            
                            # print(response_ns_dsrecord)
                            dnskey_rrsig,dnskey_rrset,ksk,ds_record_rrsig,ds_record_rrset = ObtainValues(response_ns_dsrecord, response_ns_dnskey)
                            if ds_record_rrset == None:
                              print("Could not find the DS record for the child zone from the TLD zone. Hence, DNSSEC "
                                    "not supported by this domain")
                              return "DNSSEC not supported"
                            
                            is_NS_valid = False
                            a = verify_current_server(parent_dsrecord_rrset, ksk) 
                            b = verify_dnskey_rrset(dnskey_rrset, dnskey_rrsig)
                            c = verify_ds_or_a_rrset(ds_record_rrset, ds_record_rrsig, dnskey_rrset)
                            
                            is_NS_valid = a and b and c

                            if is_NS_valid==False:
                              return -1


                            # Continue the resolution process, as DNSSec successfully validated for this Server. 
                            
                            
                            if len(response_ns_dsrecord.answer)>0 and response_ns_dsrecord.answer[0].rdtype == dns.rdatatype.A:
                                return "IP"+str(response_ns_dsrecord.answer[0][0])
                            parent_dsrecord_rrset = ds_record_rrset
                            current_response_dsrecord = response_ns_dsrecord
                            break
              

              except Exception as e:
                  print("Error when fetching from Name Server with IP {}. Error: {}".format(
                      next_ns_ip_addr, e))
            
          elif len(current_response_dsrecord.authority)>0:
            if type(current_response_dsrecord.authority[0][0]) == dns.rdtypes.ANY.NS.NS:
              for k in current_response_dsrecord.authority[0]:
                ns_domain_name = str(k)
                response_ns_dsrecord = Main_dig(ns_domain_name, 'A')
                if type(response_ns_dsrecord)==str:
                  return "DNSSEC is configured but the digital signature could NOT be verified"
                bool_sample=False
                if bool_sample==False:
                  for final_rrset in response_ns_dsrecord.answer:
                    ip = final_rrset[0].address
                    print("Authoritative Name Server IP :", ip)
                    try:
                                # Now obtain IP of the query domain from the authoritative name server
                                
                                query_auth_dsrecord= dns.message.make_query(domain_name,qtype,want_dnssec=True)
                                query_auth_dnskey= dns.message.make_query(parent_dsrecord_rrset.name.to_text(),dns.rdatatype.DNSKEY,want_dnssec=True)

                                response_auth_dsrecord = GetResponse(query_ns_dsrecord, ip)
                                response_auth_dnskey = GetResponse(query_ns_dnskey, ip)

                                print(response_ns_dsrecord)
                                dnskey_rrsig,dnskey_rrset,ksk,ds_record_rrsig,ds_record_rrset = ObtainValues(response_ns_dsrecord, response_ns_dnskey)
                                if ds_record_rrset == None:
                                  print("Could not find the DS record for the child zone from the Authorative Server zone. Hence, DNSSEC "
                                    "not supported by this domain")
                                return False
                            
                                is_auth_valid = False
                                a = verify_current_server(parent_dsrecord_rrset, ksk) 
                                b = verify_dnskey_rrset(dnskey_rrset, dnskey_rrsig)
                                c = verify_ds_or_a_rrset(ds_record_rrset, ds_record_rrsig, dnskey_rrset)
                            
                                is_auth_valid = a and b and c

                                if is_auth_valid==False:
                                  return -1

                                parent_ds_rrset = auth_ds_rrset
                                dns_response = auth_dns_response
                    except Exception as e:
                                print("Error when fetching from Authoritative Server with IP: . Error: {}".format(
                                    ip, e))
                else:
                        return response_ns_dsrecord
        
            # For SOA, we return the response
            elif type(current_response_dsrecord.authority[0][0]) == dns.rdtypes.ANY.SOA.SOA:
              return current_response_dsrecord
        if len(current_response_dsrecord.answer)>0:
          return "IP"+current_response_dsrecord.answer[0]
              
        else:
            print("Not Resolvable")
            return -1


        break

        
  return current_response_dsrecord
  

    
def verify_current_server(parent_dsrecord_rrset, ksk):
    
    if parent_dsrecord_rrset == None:
      hash_algo = 'SHA256'
      parent_ds_hash1 = root_ds[0]
      parent_ds_hash2 = root_ds[1]
      zone = '.'

    else:
      hash_algo = type_of_hash_algo.get(parent_dsrecord_rrset[0].digest_type, 2)
      parent_ds_hash1 = parent_dsrecord_rrset[0].to_text()
      parent_ds_hash2=parent_ds_hash1
      zone = parent_dsrecord_rrset.name.to_text()
    
    try:
        hash = dns.dnssec.make_ds(name = zone, key = ksk, algorithm = hash_algo).to_text()
    except dns.dnssec.ValidationFailure as e:
        print("Hash Algorithm {} not supported: {}".format(hash_algo, e))
        return False
    else:
        if hash == parent_ds_hash1 or hash==parent_ds_hash2:
            if zone == '.':
                print("PubKSK's hash matches the root_ds key digest. Root Zone "+zone+" successfully verified")
            else:
                print("PubKSK's hash matches the DSRecord RRSet from the parent zone. Hence, zone "+zone+" successfully verified")
            return True
        else:
            print("The PubKSK's hash of the '{}' zone cannot be verified by the DS record from its parent zone. Hence, "
            "DNSSec verification failed for zone '{}'".format(zone, zone))
            return False

def verify_dnskey_rrset(dnskey_rrset, dnskey_rrsig):
    try:
        dns.dnssec.validate(rrset = dnskey_rrset, rrsigset = dnskey_rrsig, keys = {dnskey_rrset.name: dnskey_rrset})
        
    except dns.dnssec.ValidationFailure as e:
        print("While verifying DNSKey RRSet using its RRSig, DNSSec verification failed for '{}' zone: {}\n".format(dnskey_rrset.name.to_text(), e))
        return False
    else:
        return True

def verify_ds_or_a_rrset(ds_record_rrset, ds_record_rrsig, dnskey_rrset):
    try:
        dns.dnssec.validate(rrset = ds_record_rrset, rrsigset = ds_record_rrsig, keys = {dnskey_rrset.name: dnskey_rrset})
    except dns.dnssec.ValidationFailure as e:
        print("While verifying DS/A RRSet using its RRSig, DNSSec verification failed for'{}' zone: {}\n".format(dnskey_rrset.name.to_text(), e))
        return False
    else:
        return True

#GetResponse is the function that is called by the Main_dig function whenever a new query is to be fired
def GetResponse(query, IP, time_out = 15):
    try:
        response = dns.query.udp(q = query, where = IP, timeout = time_out)
        return response
    except Exception as e:
        raise e


domain = sys.argv[1]
rdtype = sys.argv[2]

start = time.time()
res=Main_dig(domain,rdtype)
total = time.time() - start
date = datetime.datetime.now()
print("QUESTION SECTION")
print(domain + " IN " + rdtype)
print("ANSWER SECTION")
if "IP" in res:
  print(domain + " IN " + rdtype + " " + str(res[2::]))
else:
  print(res)
print("Query time " + "{:.2f}".format(total) + "s")
print("WHEN : " , str(date))
print("Message Size Received: "+str(sys.getsizeof(res))+' Bytes')