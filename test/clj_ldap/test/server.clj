(ns clj-ldap.test.server
  "An embedded ldap server for unit testing"
  (:require [clj-ldap.client :as ldap]
            [fs.core :as fs])
  (:import (java.util HashSet)
           (org.apache.directory.server.constants ServerDNConstants)
           (org.apache.directory.server.core DefaultDirectoryService)
           (org.apache.directory.server.core.partition.impl.btree.jdbm JdbmIndex JdbmPartition)
           (org.apache.directory.server.core.partition.ldif LdifPartition)
           (org.apache.directory.server.ldap LdapServer)
           (org.apache.directory.server.protocol.shared.transport TcpTransport)
           (org.apache.directory.shared.ldap.schema.ldif.extractor.impl DefaultSchemaLdifExtractor)
           (org.apache.directory.shared.ldap.schema.loader.ldif LdifSchemaLoader)
           (org.apache.directory.shared.ldap.schema.manager.impl DefaultSchemaManager)))

(defonce server (atom nil))

(defn- override-java-version!
  "Override the java.version property as the ancient version of
  directory-server we use for tests seems not to understand the concept of a
  version number with multiple digits (ie. 11 or 14). This version isn't
  actually used anywhere, just parsed as a side effect of loading a SystemUtils
  class, so it only needs to appear valid."
  []
  (System/setProperty "java.version" "0.0.0"))

(defn- add-partition!
  "Adds a partition to the embedded directory service"
  [service id dn]
  (let [partition (doto (JdbmPartition.)
                    (.setId id)
                    (.setPartitionDir (fs/file (.getWorkingDirectory service) id))
                    (.setSuffix dn))]
    (.addPartition service partition)
    partition))

(defn- add-index!
  "Adds an index to the given partition on the given attributes"
  [partition & attrs]
  (let [indexed-attrs (HashSet.)]
    (doseq [attr attrs]
      (.add indexed-attrs (JdbmIndex. attr)))
    (.setIndexedAttributes partition indexed-attrs)))

(defn start-ldap-server
  "Start an embedded ldap server"
  [port]
  (override-java-version!)
  (let [work-dir (fs/temp-dir)
        schema-dir (fs/file work-dir "schema")
        _ (fs/mkdir schema-dir)
        ;; Setup steps based on http://svn.apache.org/repos/asf/directory/documentation/samples/trunk/embedded-sample/src/main/java/org/apache/directory/seserver/EmbeddedADSVer157.java
        directory-service (doto (DefaultDirectoryService.)
                            (.setShutdownHookEnabled true)
                            (.setWorkingDirectory work-dir))
        schema-partition (.. directory-service (getSchemaService) (getSchemaPartition))
        ldif-partition (doto (LdifPartition.)
                        (.setWorkingDirectory (str schema-dir)))
        extractor (doto (DefaultSchemaLdifExtractor. work-dir)
                    (.extractOrCopy true))
        _ (.setWrappedPartition schema-partition ldif-partition)
        schema-manager (DefaultSchemaManager. (LdifSchemaLoader. schema-dir))
        _ (.setSchemaManager directory-service schema-manager)
        _ (.loadAllEnabled schema-manager)
        _ (.setSchemaManager schema-partition schema-manager)
        ldap-transport (TcpTransport. port)
        ldap-server (doto (LdapServer.)
                      (.setDirectoryService directory-service)
                      (.setAllowAnonymousAccess true)
                      (.setTransports
                        (into-array [ldap-transport])))]
    (->> (add-partition! directory-service "system" (ServerDNConstants/SYSTEM_DN))
         (.setSystemPartition directory-service))
    (-> (add-partition! directory-service
                        "clojure" "dc=alienscience,dc=org,dc=uk")
        (add-index! "objectClass" "ou" "uid"))
    (.startup directory-service)
    (.start ldap-server)
    [directory-service ldap-server]))

(defn- add-toplevel-objects!
  "Adds top level objects, needed for testing, to the ldap server"
  [connection]
  (ldap/add connection "dc=alienscience,dc=org,dc=uk"
            {:objectClass ["top" "domain" "extensibleObject"]
             :dc "alienscience"})
  (ldap/add connection "ou=people,dc=alienscience,dc=org,dc=uk"
            {:objectClass ["top" "organizationalUnit"]
             :ou "people"})
  (ldap/add connection
            "cn=Saul Hazledine,ou=people,dc=alienscience,dc=org,dc=uk"
            {:objectClass ["top" "Person"]
             :cn "Saul Hazledine"
             :sn "Hazledine"
             :description "Creator of bugs"}))

(defn stop!
  "Stops the embedded ldap server"
  []
  (if @server
    (let [[directory-service ldap-server] @server]
      (reset! server nil)
      (.stop ldap-server)
      (.shutdown directory-service))))

(defn start!
  "Starts an embedded ldap server on the given port"
  [port]
  (stop!)
  (reset! server (start-ldap-server port))
  (let [conn (ldap/connect {:host {:address "localhost" :port port}})]
    (add-toplevel-objects! conn)))
