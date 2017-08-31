package utils

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/vishvananda/netlink"
	"io"
	"net"
	"os"
       //	"reflect"
	"syscall"
	"strconv"
)

// DoNetworking performs the networking for the given config and IPAM result
func DoNetworking(args *skel.CmdArgs, conf NetConf, result *current.Result, logger *log.Entry, desiredVethName string, ingress_bandwidth string, egress_bandwidth string) (hostVethName, contVethMAC string, err error) {
	// Select the first 11 characters of the containerID for the host veth.
	hostVethName = "cali" + args.ContainerID[:Min(11, len(args.ContainerID))]
	contVethName := args.IfName
	var hasIPv4, hasIPv6 bool
        Rate1, err := strconv.Atoi(ingress_bandwidth)
                if err != nil {
                 fmt.Println("convert fail")
         }
                if Rate1<0 {
                        fmt.Println("rate1 error")
                }

             Rate2, err := strconv.Atoi(egress_bandwidth)
                if err != nil {
                 fmt.Println("convert fail")

                              }
                if Rate2<0 {
                        fmt.Println("rate2 error")
                }



	// If a desired veth name was passed in, use that instead.
	if desiredVethName != "" {
		hostVethName = desiredVethName
	}

	// Clean up if hostVeth exists.
	if oldHostVeth, err := netlink.LinkByName(hostVethName); err == nil {
		if err = netlink.LinkDel(oldHostVeth); err != nil {
			return "", "", fmt.Errorf("failed to delete old hostVeth %v: %v", hostVethName, err)
		}
		logger.Infof("clean old hostVeth: %v", hostVethName)
	}

	err = ns.WithNetNSPath(args.Netns, func(hostNS ns.NetNS) error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name:  contVethName,
				Flags: net.FlagUp,
				MTU:   conf.MTU,
			},
			PeerName: hostVethName,
		}

		if err := netlink.LinkAdd(veth); err != nil {
			logger.Errorf("Error adding veth %+v: %s", veth, err)
			return err
		}

		hostVeth, err := netlink.LinkByName(hostVethName)
		if err != nil {
			err = fmt.Errorf("failed to lookup %q: %v", hostVethName, err)
			return err
		}

		// Explicitly set the veth to UP state, because netlink doesn't always do that on all the platforms with net.FlagUp.
		// veth won't get a link local address unless it's set to UP state.
		if err = netlink.LinkSetUp(hostVeth); err != nil {
			return fmt.Errorf("failed to set %q up: %v", hostVethName, err)
		}

		contVeth, err := netlink.LinkByName(contVethName)
		if err != nil {
			err = fmt.Errorf("failed to lookup %q: %v", contVethName, err)
			return err
		}

		// Fetch the MAC from the container Veth. This is needed by Calico.
		contVethMAC = contVeth.Attrs().HardwareAddr.String()
		logger.WithField("MAC", contVethMAC).Debug("Found MAC for container veth")

		// At this point, the virtual ethernet pair has been created, and both ends have the right names.
		// Both ends of the veth are still in the container's network namespace.

		for _, addr := range result.IPs {

			// Before returning, create the routes inside the namespace, first for IPv4 then IPv6.
			if addr.Version == "4" {
				// Add a connected route to a dummy next hop so that a default route can be set
				gw := net.IPv4(169, 254, 1, 1)
				gwNet := &net.IPNet{IP: gw, Mask: net.CIDRMask(32, 32)}
				if err = netlink.RouteAdd(&netlink.Route{
					LinkIndex: contVeth.Attrs().Index,
					Scope:     netlink.SCOPE_LINK,
					Dst:       gwNet}); err != nil {
					return fmt.Errorf("failed to add route %v", err)
				}

				if err = ip.AddDefaultRoute(gw, contVeth); err != nil {
					return fmt.Errorf("failed to add route %v", err)
				}

				if err = netlink.AddrAdd(contVeth, &netlink.Addr{IPNet: &addr.Address}); err != nil {
					return fmt.Errorf("failed to add IP addr to %q: %v", contVethName, err)
				}
				// Set hasIPv4 to true so sysctls for IPv4 can be programmed when the host side of
				// the veth finishes moving to the host namespace.
				hasIPv4 = true
			}

			// Handle IPv6 routes
			if addr.Version == "6" {
				// No need to add a dummy next hop route as the host veth device will already have an IPv6
				// link local address that can be used as a next hop.
				// Just fetch the address of the host end of the veth and use it as the next hop.
				addresses, err := netlink.AddrList(hostVeth, netlink.FAMILY_V6)
				if err != nil {
					logger.Errorf("Error listing IPv6 addresses: %s", err)
					return err
				}

				if len(addresses) < 1 {
					// If the hostVeth doesn't have an IPv6 address then this host probably doesn't
					// support IPv6. Since a IPv6 address has been allocated that can't be used,
					// return an error.
					return fmt.Errorf("failed to get IPv6 addresses for host side of the veth pair")
				}

				hostIPv6Addr := addresses[0].IP

				_, defNet, _ := net.ParseCIDR("::/0")
				if err = ip.AddRoute(defNet, hostIPv6Addr, contVeth); err != nil {
					return fmt.Errorf("failed to add default gateway to %v %v", hostIPv6Addr, err)
				}

				if err = netlink.AddrAdd(contVeth, &netlink.Addr{IPNet: &addr.Address}); err != nil {
					return fmt.Errorf("failed to add IP addr to %q: %v", contVeth, err)
				}

				// Set hasIPv6 to true so sysctls for IPv6 can be programmed when the host side of
				// the veth finishes moving to the host namespace.
				hasIPv6 = true
			}
		}
               
                /*Rate1, err := strconv.Atoi(ingress_bandwidth)
                if err != nil {
                 fmt.Println("convert fail")
         }
                if Rate1<0 {
                        fmt.Println("rate1 error")
                }

             Rate2, err := strconv.Atoi(egress_bandwidth)
                if err != nil {
                 fmt.Println("convert fail")

                              }
                if Rate2<0 {
                        fmt.Println("rate2 error")
                }

*/

                index := contVeth.Attrs().Index
		qdiscHandle := netlink.MakeHandle(0x1, 0x0)
        qdiscAttrs := netlink.QdiscAttrs{
                LinkIndex: index,
                Handle:    qdiscHandle,
                Parent:    netlink.HANDLE_ROOT,
        }
        qdisc := netlink.NewHtb(qdiscAttrs)
        if err := netlink.QdiscAdd(qdisc); err != nil {
                fmt.Println("add qdisc err")
        }

        classId := netlink.MakeHandle(0x1, 0x66cb)
        classAttrs := netlink.ClassAttrs{
                LinkIndex: index,
                Parent:    qdiscHandle,
                Handle:    classId,
        }
        htbClassAttrs := netlink.HtbClassAttrs{
                Rate:   uint64(Rate2),
                Buffer: 320000 * 1024,
        }
        htbClass := netlink.NewHtbClass(classAttrs, htbClassAttrs)
        if err = netlink.ClassReplace(htbClass); err != nil {
                fmt.Println("Failed to add a HTB class: %v", err)
        }
        u32SelKeys :=[]netlink.TcU32Key{
              
                  netlink.TcU32Key{
                        Mask:    0xffffff00,
                        Val:     0xc0a8a200,
                        Off:     16,
                        OffMask: 0,
                },
               
				}
               filter := &netlink.U32{
                FilterAttrs: netlink.FilterAttrs{
                        LinkIndex: index,
                        Parent:    qdiscHandle,
                        Priority:  1,
                        Protocol:  syscall.ETH_P_IP,
                },
                Sel: &netlink.TcU32Sel{
                        Keys:  u32SelKeys,
                        Flags: netlink.TC_U32_TERMINAL,
                },
                ClassId: classId,
                Actions: []netlink.Action{},
        }

        if err := netlink.FilterAdd(filter); err != nil {
                fmt.Println("add filter err")
        }


		// Now that the everything has been successfully set up in the container, move the "host" end of the
		// veth into the host namespace.
		if err = netlink.LinkSetNsFd(hostVeth, int(hostNS.Fd())); err != nil {
			return fmt.Errorf("failed to move veth to host netns: %v", err)
		}

		return nil
	})

	if err != nil {
		logger.Errorf("Error creating veth: %s", err)
		return "", "", err
	}
	
	err = configureSysctls(hostVethName, hasIPv4, hasIPv6)
	if err != nil {
		return "", "", fmt.Errorf("error configuring sysctls for interface: %s, error: %s", hostVethName, err)
	}

	// Moving a veth between namespaces always leaves it in the "DOWN" state. Set it back to "UP" now that we're
	// back in the host namespace.
	hostVeth, err := netlink.LinkByName(hostVethName)
	if err != nil {
		return "", "", fmt.Errorf("failed to lookup %q: %v", hostVethName, err)
	}

	if err = netlink.LinkSetUp(hostVeth); err != nil {
		return "", "", fmt.Errorf("failed to set %q up: %v", hostVethName, err)
	}
        
	// Now that the host side of the veth is moved, state set to UP, and configured with sysctls, we can add the routes to it in the host namespace.
	err = setupRoutes(hostVeth, result)
	if err != nil {
		return "", "", fmt.Errorf("error adding host side routes for interface: %s, error: %s", hostVeth.Attrs().Name, err)
	
	
     }
             
             //ingress_bandwidth = "123456"
  //           logger.Infof("lj: %s  HELLO", ingress_bandwidth)
              
/*	     Rate1, err := strconv.Atoi(ingress_bandwidth)
                if err != nil {
		 fmt.Println("convert fail")
	 }
	        if Rate1<0 {
			fmt.Println("rate1 error")
		}
	 
	     Rate2, err := strconv.Atoi(egress_bandwidth)
	        if err != nil {
	         fmt.Println("convert fail")

			      }
	        if Rate2<0 {
			fmt.Println("rate2 error")
		}
*/
//		Rate1=5000000
//		Rate2=5000000
//	logger.Infof("lj speed: %s", Rate1)
                
               	index1 := hostVeth.Attrs().Index
		qdiscHandle1 := netlink.MakeHandle(0x1, 0x0)
		qdiscAttrs1 := netlink.QdiscAttrs{
			LinkIndex: index1,
			Handle:    qdiscHandle1,
			Parent:    netlink.HANDLE_ROOT,
		}
		qdisc1 := netlink.NewHtb(qdiscAttrs1)
		if err := netlink.QdiscAdd(qdisc1); err != nil {
			fmt.Println("add qdisc err")
		}

		qdiscs, err := netlink.QdiscList(hostVeth)
		if err != nil {
			fmt.Println("list qdisc err")
		}
		if len(qdiscs) != 1 {
			fmt.Println("Failed to add qdisc")
		}

		classId1 := netlink.MakeHandle(0x1, 0x56cb)

                classAttrs1 := netlink.ClassAttrs{
                LinkIndex: index1,
                Parent:    qdiscHandle1,
                Handle:    classId1,
        }
        htbClassAttrs1 := netlink.HtbClassAttrs{
                Rate:   uint64(Rate1),
                Buffer: 320000 * 1024,
        }
        htbClass1 := netlink.NewHtbClass(classAttrs1, htbClassAttrs1)

        if err = netlink.ClassReplace(htbClass1); err != nil {
        fmt.Println("Failed to add a HTB class1: %v", err)
        }
        
        classId2 := netlink.MakeHandle(0x1, 0x66cb)

                classAttrs2 := netlink.ClassAttrs{
                LinkIndex: index1,
                Parent:    qdiscHandle1,
                Handle:    classId2,
        }
        htbClassAttrs2 := netlink.HtbClassAttrs{
                Rate:   uint64(Rate1),
                Buffer: 320000 * 1024,
        }
        htbClass2 := netlink.NewHtbClass(classAttrs2, htbClassAttrs2)

        if err = netlink.ClassReplace(htbClass2); err != nil {
        fmt.Println("Failed to add a HTB class1: %v", err)
        }

        u32SelKeys1 := []netlink.TcU32Key{
        netlink.TcU32Key{
                        Mask:    0x00000000,
                        Val:     0x00000000,
                        Off:     16,
                        OffMask: 0,
                },
        }


        filter1 := &netlink.U32{
                FilterAttrs: netlink.FilterAttrs{
                        LinkIndex: index1,
                        Parent:    qdiscHandle1,
                        Priority:  1,
                        Protocol:  syscall.ETH_P_IP,
                },
               Sel: &netlink.TcU32Sel{
                        Keys:  u32SelKeys1,
                        Flags: netlink.TC_U32_TERMINAL,
                },
                ClassId: classId1,
                Actions: []netlink.Action{},
        }

        if err := netlink.FilterAdd(filter1); err != nil {
                fmt.Println("add filter1 err")
        }

        u32SelKeys2 := []netlink.TcU32Key{
        netlink.TcU32Key{
                        Mask:    0x00000000,
                        Val:     0x00000000,
                        Off:     12,
                        OffMask: 0,
                },
        }
        filter2 := &netlink.U32{
                FilterAttrs: netlink.FilterAttrs{
                        LinkIndex: index1,
                        Parent:    qdiscHandle1,
                        Priority:  2,
                        Protocol:  syscall.ETH_P_IP,
                },
               Sel: &netlink.TcU32Sel{
                        Keys:  u32SelKeys2,
                        Flags: netlink.TC_U32_TERMINAL,
                },
                ClassId: classId2,
                Actions: []netlink.Action{},
        }

        if err := netlink.FilterAdd(filter2); err != nil {
                fmt.Println("add filter1 err")
        }

        
	return hostVethName, contVethMAC, err
}

// setupRoutes sets up the routes for the host side of the veth pair.
func setupRoutes(hostVeth netlink.Link, result *current.Result) error {
	for _, ip := range result.IPs {
		err := netlink.RouteAdd(
			&netlink.Route{
				LinkIndex: hostVeth.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				Dst:       &ip.Address,
			})
		if err != nil {
			return fmt.Errorf("failed to add route %v", err)
		}

		log.Debugf("CNI adding route for interface: %v, IP: %s", hostVeth, ip.Address)
	}
	return nil
}

// configureSysctls configures necessary sysctls required for the host side of the veth pair for IPv4 and/or IPv6.
func configureSysctls(hostVethName string, hasIPv4, hasIPv6 bool) error {
	var err error

	if hasIPv4 {
		// Enable proxy ARP, this makes the host respond to all ARP requests with its own
		// MAC. We install explicit routes into the containers network
		// namespace and we use a link-local address for the gateway.  Turing on proxy ARP
		// means that we don't need to assign the link local address explicitly to each
		// host side of the veth, which is one fewer thing to maintain and one fewer
		// thing we may clash over.
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/proxy_arp", hostVethName), "1"); err != nil {
			return err
		}

		// Normally, the kernel has a delay before responding to proxy ARP but we know
		// that's not needed in a Calico network so we disable it.
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/neigh/%s/proxy_delay", hostVethName), "0"); err != nil {
			return err
		}

		// Enable IP forwarding of packets coming _from_ this interface.  For packets to
		// be forwarded in both directions we need this flag to be set on the fabric-facing
		// interface too (or for the global default to be set).
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/forwarding", hostVethName), "1"); err != nil {
			return err
		}
	}

	if hasIPv6 {
		// Enable proxy NDP, similarly to proxy ARP, described above in IPv4 section.
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/proxy_ndp", hostVethName), "1"); err != nil {
			return err
		}

		// Enable IP forwarding of packets coming _from_ this interface.  For packets to
		// be forwarded in both directions we need this flag to be set on the fabric-facing
		// interface too (or for the global default to be set).
		if err = writeProcSys(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/forwarding", hostVethName), "1"); err != nil {
			return err
		}
	}

	return nil
}

// writeProcSys takes the sysctl path and a string value to set i.e. "0" or "1" and sets the sysctl.
func writeProcSys(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	n, err := f.Write([]byte(value))
	if err == nil && n < len(value) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}
