(ns clj-ldap.client
  "LDAP client"
  (:refer-clojure :exclude [get])
  (:require [clojure.string :as string]
            [clojure.tools.logging :as log])
  (:import (com.unboundid.asn1 ASN1OctetString)
           (com.unboundid.ldap.sdk
             BindRequest Control LDAPConnectionOptions
             LDAPConnection
             LDAPResult ReadOnlyEntry ResultCode
             LDAPConnectionPool
             LDAPException
             Attribute
             Entry
             ModificationType
             ModifyRequest
             ModifyDNRequest
             Modification
             DeleteRequest
             SimpleBindRequest
             RoundRobinServerSet
             SearchRequest
             LDAPEntrySource
             EntrySourceException
             SearchScope UpdatableLDAPRequest)
           (com.unboundid.ldap.sdk.extensions
             PasswordModifyExtendedRequest
             StartTLSExtendedRequest)
           (com.unboundid.ldap.sdk.controls
             PreReadRequestControl
             PostReadRequestControl
             PreReadResponseControl
             PostReadResponseControl
             SimplePagedResultsControl)
           (com.unboundid.util.ssl
             SSLUtil TrustAllTrustManager
             HostNameSSLSocketVerifier)
           (com.puppetlabs.ldap Utils)
           (javax.net.ssl SSLSocketFactory)))

;;======== Helper functions ====================================================

(def not-nil? (complement nil?))

(defn encode ^String [^Attribute attr]
  (.getValue attr))

(defn ssl-protocol-mapping
  "Converts user protocol settings into valid string constants"
  [ssl-protocols]
  (let [valid-protocols #{"TLSv1.3" "TLSv1.2" "TLSv1.1" "TLSv1"}
        valid-ssl-protocols (filter #(contains? valid-protocols %) ssl-protocols)
        invalid-ssl-protocols (remove #(contains? valid-protocols %) ssl-protocols)]
    (when (not-nil? invalid-ssl-protocols)
      (log/infof "Unsuported value %s passed into SSL protocol" invalid-ssl-protocols)
      (log/infof "Removing %s from ssl-protocol" invalid-ssl-protocols))
    (replace 
     {"TLSv1.3" SSLUtil/SSL_PROTOCOL_TLS_1_3 
      "TLSv1.2" SSLUtil/SSL_PROTOCOL_TLS_1_2 
      "TLSv1.1" SSLUtil/SSL_PROTOCOL_TLS_1_1, 
      "TLSv1" SSLUtil/SSL_PROTOCOL_TLS_1} valid-ssl-protocols)))

(defn- extract-attribute
  "Extracts [:name value] from the given attribute object. Converts
   the objectClass attribute to a set."
  [^Attribute attr]
  (let [k (keyword (.getName attr))]
    (cond
      (= :objectClass k)     [k (set (vec (.getValues attr)))]
      (> (.size attr) 1)     [k (vec (.getValues attr))]
      :else                  [k (encode attr)])))

(defn- entry-as-map
  "Converts an Entry object into a map optionally adding the DN"
  ([^ReadOnlyEntry entry]
   (entry-as-map entry true))
  ([^ReadOnlyEntry entry dn?]
   (let [attrs (seq (.getAttributes entry))]
       (if dn?
         (apply hash-map :dn (.getDN entry)
                (mapcat extract-attribute attrs))
         (apply hash-map
                (mapcat extract-attribute attrs))))))

(defn- add-response-control
  "Adds the values contained in given response control to the given map"
  [m control]
  (condp instance? control
    PreReadResponseControl
    (update-in m [:pre-read] merge (entry-as-map (.getEntry ^PreReadResponseControl control) false))
    PostReadResponseControl
    (update-in m [:post-read] merge (entry-as-map (.getEntry ^PostReadResponseControl control) false))
    m))

(defn- add-response-controls
  "Adds the values contained in the given response controls to the given map"
  [controls m]
  (reduce add-response-control m (seq controls)))

(defn- ldap-result
  "Converts an LDAPResult object into a map"
  [^LDAPResult obj]
  (let [res (.getResultCode obj)
        controls (.getResponseControls obj)]
    (add-response-controls
     controls
     {:code (.intValue res)
      :name (.getName res)})))

(defn- connection-options
  "Returns a LDAPConnectionOptions object"
  ^LDAPConnectionOptions [{:keys [connect-timeout timeout verify-host? wildcard-host?]}]
  (let [opt (LDAPConnectionOptions.)]
    (when connect-timeout      (.setConnectTimeoutMillis opt connect-timeout))
    (when timeout              (.setResponseTimeoutMillis opt timeout))
    (when (true? verify-host?) (.setSSLSocketVerifier opt (HostNameSSLSocketVerifier. (true? wildcard-host?))))
    opt))

(defn- create-ssl-util
  "If the trust-manager is truthy, returns a SSLUtil created with
  it; otherwise, if trust-store is truthy, returns a SSLUtil created with
  it. If both are falsy, returns a SSLUtil created with a TrustAllTrustManager."
  [trust-managers trust-store]
  (if trust-managers
    (Utils/trustManagersToSSLUtil trust-managers)
    (if trust-store
      (Utils/trustStoreToSSLUtil trust-store)
      (Utils/trustManagerToSSLUtil
        (TrustAllTrustManager.)))))

(defn- create-ssl-factory
  "Returns a SSLSocketFactory object"
  ^SSLSocketFactory [{:keys [trust-managers trust-store cipher-suites ssl-protocols]}]
  (let [^SSLUtil ssl-util (create-ssl-util trust-managers trust-store)] 
    (when (not-nil? cipher-suites)
      (SSLUtil/setEnabledSSLCipherSuites cipher-suites))
    (when (not-nil? ssl-protocols) 
      (SSLUtil/setEnabledSSLProtocols (ssl-protocol-mapping ssl-protocols)))
    (.createSSLSocketFactory ssl-util)))

(defn- host-as-map
  "Returns a single host as a map containing an :address and an optional
   :port"
  [host]
  (cond
    (nil? host)      {:address "localhost" :port 389}
    (string? host)   (let [[address port] (string/split host #":")]
                       {:address (if (= address "")
                                   "localhost"
                                   address)
                        :port (when port
                                (if (string? port)
                                  (int (Integer/parseInt port))
                                  port))})
    (map? host)      (merge {:address "localhost"} host)
    :else            (throw
                      (IllegalArgumentException.
                       (str "Invalid host for an ldap connection : "
                            host)))))

(defn- create-connection
  "Create an LDAPConnection object"
  ^LDAPConnection [{:keys [host ssl? start-tls?] :as options}]
  (let [h (host-as-map host)
        ^LDAPConnectionOptions opt (connection-options options)
        ^String address (:address h)
        ^int effective-port (or (:port h) 389)
        ^int effective-ssl-port (or (:port h) 636)]
    (cond
      (and ssl? start-tls?)
      (throw (IllegalArgumentException. "Can't have both SSL and startTLS"))

      ssl?
      (LDAPConnection. ^SSLSocketFactory (create-ssl-factory options) opt address effective-ssl-port)

      start-tls?
      (let [start-tls-req (StartTLSExtendedRequest. (create-ssl-factory options))]
        (doto (LDAPConnection. opt address effective-port)
          (.processExtendedOperation start-tls-req)))

      :else
      (LDAPConnection. opt address effective-port))))

(defn- bind-request
  "Returns a BindRequest object"
  ^BindRequest [{:keys [bind-dn password]}]
  (if bind-dn
    (SimpleBindRequest. ^String bind-dn ^String password)
    (SimpleBindRequest.)))

(defn- connect-to-host
  "Connect to a single host"
  [options]
  (let [{:keys [num-connections]} options
        connection (create-connection options)
        bind-result (.bind connection (bind-request options))]
    (if (= ResultCode/SUCCESS (.getResultCode bind-result))
      (LDAPConnectionPool. connection (or num-connections 1))
      (throw (LDAPException. bind-result)))))

(defn- create-server-set
  "Returns a RoundRobinServerSet"
  ^RoundRobinServerSet [{:keys [host ssl?] :as options}]
  (let [hosts (map host-as-map host)
        ^"[Ljava.lang.String;" addresses (into-array String (map :address hosts))
        ^LDAPConnectionOptions opt (connection-options options)]
    (if ssl?
      (let [ssl (create-ssl-factory options)
            ^"[I" ports (int-array (map #(or (:port %) (int 636)) hosts))]
        (RoundRobinServerSet. addresses ports ssl opt))
      (let [^"[I" ports (int-array (map #(or (:port %) (int 389)) hosts))]
        (RoundRobinServerSet. addresses ports opt)))))

(defn- connect-to-hosts
  "Connects to multiple hosts"
  [options]
  (let [{:keys [num-connections]} options
        ^RoundRobinServerSet server-set (create-server-set options)
        ^BindRequest bind-request (bind-request options)
        ^int connections (or num-connections 1)]
    (LDAPConnectionPool. server-set bind-request connections)))

(defn- set-entry-kv!
  "Sets the given key/value pair in the given entry object"
  [^Entry entry-obj k v]
  (let [name-str (name k)]
    (.addAttribute entry-obj
                   (if (coll? v)
                     (let [^"[Ljava.lang.String;" values (into-array String v)]
                       (Attribute. name-str values))
                     (Attribute. name-str (str v))))))

(defn- set-entry-map!
  "Sets the attributes in the given entry object using the given map"
  [entry-obj m]
  (doseq [[k v] m]
    (set-entry-kv! entry-obj k v)))

(defn- create-modification
  "Creates a modification object"
  [^ModificationType modify-op ^String attribute values]
  (cond
    (coll? values)    (if (string? (first values))
                        (let [^"[Ljava.lang.String;" string-values (into-array String values)]
                           (Modification. modify-op attribute string-values))
                        (let [^"[Lcom.unboundid.asn1.ASN1OctetString;" octet-values (into-array ASN1OctetString values)]
                          (Modification. modify-op attribute octet-values)))
    (bytes? values)   (Modification. modify-op attribute ^"[B" values)
    (= :all values)   (Modification. modify-op attribute)
    :else             (Modification. modify-op attribute (str values))))

(defn- modify-ops
  "Returns a sequence of Modification objects to do the given operation
   using the contents of the given map."
  [^ModificationType modify-op modify-map]
  (for [[k v] modify-map]
    (create-modification modify-op (name k) v)))

(defn- add-request-controls
  "Adds LDAP controls to the given request"
  [^UpdatableLDAPRequest request options]
  (when (contains? options :pre-read)
    (let [attributes (map name (options :pre-read))
          pre-read-control (PreReadRequestControl. ^"[Ljava.lang.String;" (into-array String attributes))]
      (.addControl request pre-read-control)))
  (when (contains? options :post-read)
    (let [attributes (map name (options :post-read))
          pre-read-control (PostReadRequestControl. ^"[Ljava.lang.String;" (into-array String attributes))]
      (.addControl request pre-read-control))))


(defn- get-modify-request
  "Sets up a ModifyRequest object using the contents of the given map"
  ^ModifyRequest [^String dn modifications]
  (let [adds (modify-ops ModificationType/ADD (modifications :add))
        deletes (modify-ops ModificationType/DELETE (modifications :delete))
        replacements (modify-ops ModificationType/REPLACE
                                 (modifications :replace))
        increments (modify-ops ModificationType/INCREMENT
                               (modifications :increment))
        all (concat adds deletes replacements increments)
        ^"[Lcom.unboundid.ldap.sdk.Modification;" as-array (into-array Modification all)]
    (doto (ModifyRequest. dn as-array)
      (add-request-controls modifications))))

(defn- entry-seq
  "Returns a lazy sequence of entries from an LDAPEntrySource object"
  [^LDAPEntrySource source]
  (when-let [n (.nextEntry source)]
    (cons n (lazy-seq (entry-seq source)))))

;; Extended version of search-results function using a
;; SearchRequest that uses a SimplePagedResultsControl.
;; Allows us to read arbitrarily large result sets.
;; TODO make this lazy
(defn- search-all-results
  "Returns a sequence of search results via paging so we don't run into
   size limits with the number of results."
  [^LDAPConnectionPool connection criteria]
  (let [sizeLimit 500
        ^String base (:base criteria)
        ^SearchScope scope (:scope criteria)
        ^String filter (:filter criteria)
        ^"[Ljava.lang.String;" attributes (:attributes criteria)
        ^SearchRequest req (SearchRequest. base scope filter attributes)]
    (loop [results []
           cookie nil]
      (let [^"[Lcom.unboundid.ldap.sdk.Control;" page-results-array (make-array Control (SimplePagedResultsControl. sizeLimit cookie))]
        (.setControls req page-results-array))
      (let [res (.search connection req)
            control (SimplePagedResultsControl/get res)
            newres (->> (.getSearchEntries res)
                     (map entry-as-map)
                     (remove empty?)
                     (into results))]
        (if (and
              (not-nil? control)
              (> (.getValueLength (.getCookie control)) 0))
          (recur newres (.getCookie control))
          (seq newres))))))

(defn- search-results
  "Returns a sequence of search results for the given search criteria."
  [^LDAPConnectionPool connection criteria]
  (let [^String base (:base criteria)
        ^SearchScope scope (:scope criteria)
        ^String filter (:filter criteria)
        ^"[Ljava.lang.String;" attributes (:attributes criteria)
        res (.search connection base scope filter attributes)]
    (when (> (.getEntryCount res) 0)
      (remove empty?
              (map entry-as-map (.getSearchEntries res))))))

(defn- search-results!
  "Call the given function with the results of the search using
   the given search criteria"
  [^LDAPConnectionPool pool criteria _queue-size f]
  (let [^String base (:base criteria)
        ^SearchScope scope (:scope criteria)
        ^String filter (:filter criteria)
        ^"[Ljava.lang.String;" attributes (:attributes criteria)
        request (SearchRequest. base scope filter attributes)
        conn (.getConnection pool)]
    (try
      (with-open [source (LDAPEntrySource. conn request false)]
        (doseq [i (remove empty?
                          (map entry-as-map (entry-seq source)))]
          (f i)))
      (.releaseConnection pool conn)
      (catch EntrySourceException e
        (.releaseDefunctConnection pool conn)
        (throw e)))))


(defn- get-scope
  "Converts a keyword into a SearchScope object"
  [k]
  (condp = k
    :base SearchScope/BASE
    :one  SearchScope/ONE
    SearchScope/SUB))

(defn- get-attributes
  "Converts a collection of attributes into an array"
  [attrs]
  (cond
    (or (nil? attrs)
        (empty? attrs))    (into-array String
                                       [SearchRequest/ALL_USER_ATTRIBUTES])
    :else                  (into-array String
                                       (map name attrs))))

(defn- search-criteria
  "Returns a map of search criteria from the given base and options"
  [base options]
  (let [scope (get-scope (:scope options))
        filter (or (:filter options) "(objectclass=*)")
        attributes (get-attributes (:attributes options))]
    {:base base
     :scope scope
     :filter filter
     :attributes attributes}))

;;=========== API ==============================================================

(defn connect
  "Connects to an ldap server and returns a thread-safe LDAPConnectionPool.
   Options is a map with the following entries:
   :host            Either a string in the form \"address:port\"
                    OR a map containing the keys,
                       :address   defaults to localhost
                       :port      defaults to 389 (or 636 for ldaps),
                    OR a collection containing multiple hosts used for load
                    balancing and failover. This entry is optional.
   :bind-dn         The DN to bind as, optional
   :password        The password to bind with, optional
   :num-connections The number of connections in the pool, defaults to 1
   :ssl?            Boolean, connect over SSL (ldaps), defaults to false
   :cipher-suites   An optional set of strings corresponding to SSL
                    cipher suites, defaults to nil
   :ssl-protocols   An optional set of strings corresponding to SSL
                    protocols. TLSv1.3, TLSv1.2, TLSv1.1, & TLSv1 are
                    supported options, defaults to nil
   :start-tls?      Boolean, use startTLS to initiate TLS on an otherwise
                    unsecured connection, defaults to false.
   :trust-store     Only trust SSL certificates that are in this
                    JKS format file, optional, defaults to trusting all
                    certificates
   :trust-managers  An optional TrustManager array to be used in place of
                    a temporary keystore to create an SSLSocketFactory.
   :verify-host?    Verifies the hostname of the specified certificate,
                    false by default.
   :wildcard-host?  Allows wildcard in certificate hostname verification,
                    false by default.
   :connect-timeout The timeout for making connections (milliseconds),
                    defaults to 1 minute
   :timeout         The timeout when waiting for a response from the server
                    (milliseconds), defaults to 5 minutes
   "
  [options]
  (let [host (options :host)]
    (if (and (coll? host)
             (not (map? host)))
      (connect-to-hosts options)
      (connect-to-host options))))

(defn bind?
  "Performs a bind operation using the provided connection, bindDN and
password. Returns true if successful.

When an LDAP connection object is used as the connection argument the
bind? function will attempt to change the identity of that connection
to that of the provided DN. Subsequent operations on that connection
will be done using the bound identity.

If an LDAP connection pool object is passed as the connection argument
the bind attempt will have no side-effects, leaving the state of the
underlying connections unchanged."
  [connection bind-dn password]
  (try
    (let [bind-result (.bind ^LDAPConnectionPool connection bind-dn password)]
      (if (= ResultCode/SUCCESS (.getResultCode bind-result)) true false))
    (catch Exception _ false)))

(defn get
  "If successful, returns a map containing the entry for the given DN.
   Returns nil if the entry doesn't exist or cannot be read. Takes an
   optional collection that specifies which attributes will be returned
   from the server."
  ([connection dn]
   (get connection dn nil))
  ([^LDAPConnectionPool connection dn attributes]
   (when-let [result (if attributes
                         (.getEntry connection dn
                                    (into-array String
                                                (map name attributes)))
                         (.getEntry connection dn))]
        (entry-as-map result))))

(defn add
  "Adds an entry to the connected ldap server. The entry is assumed to be
   a map."
  [^LDAPConnectionPool connection ^String dn entry]
  (let [entry-obj (Entry. dn)]
    (set-entry-map! entry-obj entry)
    (ldap-result
     (.add connection entry-obj))))

(defn modify
  "Modifies an entry in the connected ldap server. The modifications are
   a map in the form:
     {:add
        {:attribute-a some-value
         :attribute-b [value1 value2]}
      :delete
        {:attribute-c :all
         :attribute-d some-value
         :attribute-e [value1 value2]}
      :replace
        {:attibute-d value
         :attribute-e [value1 value2]}
      :increment
        {:attribute-f value}
      :pre-read
        #{:attribute-a :attribute-b}
      :post-read
        #{:attribute-c :attribute-d}}

Where :add adds an attribute value, :delete deletes an attribute value and
:replace replaces the set of values for the attribute with the ones specified.
The entries :pre-read and :post-read specify attributes that have be read and
returned either before or after the modifications have taken place."
  [^LDAPConnectionPool connection dn modifications]
  (let [modify-obj (get-modify-request dn modifications)]
    (ldap-result
     (.modify connection modify-obj))))

(defn modify-password
  "Creates a new password modify extended request that will attempt to change
   the password of the currently-authenticated user, or another user if their
   DN is provided and the caller has the required authorisation."
  ([^LDAPConnectionPool connection ^String new]
   (let [request (PasswordModifyExtendedRequest. new)]
      (.processExtendedOperation connection request)))

  ([^LDAPConnectionPool connection ^String old ^String new]
   (let [request (PasswordModifyExtendedRequest. old new)]
      (.processExtendedOperation connection request)))

  ([^LDAPConnectionPool connection ^String old ^String new ^String dn]
   (let [request (PasswordModifyExtendedRequest. dn old new)]
      (.processExtendedOperation connection request))))

(defn modify-rdn
  "Modifies the RDN (Relative Distinguished Name) of an entry in the connected
  ldap server.

  The new-rdn has the form cn=foo or ou=foo. Using just foo is not sufficient.
  The delete-old-rdn boolean option indicates whether to delete the current
  RDN value from the target entry."
  [^LDAPConnectionPool connection ^String dn ^String new-rdn ^Boolean delete-old-rdn]
  (let [request (ModifyDNRequest. dn new-rdn delete-old-rdn)]
    (ldap-result
      (.modifyDN connection request))))

(defn delete
  "Deletes the given entry in the connected ldap server. Optionally takes
   a map that can contain the entry :pre-read to indicate the attributes
   that should be read before deletion."
  ([^LDAPConnectionPool connection ^String dn]
   (delete connection dn nil))
  ([^LDAPConnectionPool connection ^String dn options]
   (let [delete-obj (DeleteRequest. dn)]
       (when options
         (add-request-controls delete-obj options))
       (ldap-result
        (.delete connection delete-obj)))))

(defn search-all
  "Runs a search on the connected ldap server, reads all the results into
   memory and returns the results as a sequence of maps.

   Options is a map with the following optional entries:
      :scope       The search scope, can be :base :one or :sub,
                   defaults to :sub
      :filter      A string describing the search filter,
                   defaults to \"(objectclass=*)\"
      :attributes  A collection of the attributes to return,
                   defaults to all user attributes"
  ([connection base]
   (search-all connection base nil))
  ([connection base options]
   (search-all-results connection (search-criteria base options))))

(defn search
  "Runs a search on the connected ldap server, reads all the results into
   memory and returns the results as a sequence of maps.

   Options is a map with the following optional entries:
      :scope       The search scope, can be :base :one or :sub,
                   defaults to :sub
      :filter      A string describing the search filter,
                   defaults to \"(objectclass=*)\"
      :attributes  A collection of the attributes to return,
                   defaults to all user attributes"
  ([connection base]
   (search connection base nil))
  ([connection base options]
   (search-results connection (search-criteria base options))))

(defn search!
  "Runs a search on the connected ldap server and executes the given
   function (for side effects) on each result. Does not read all the
   results into memory.

   Options is a map with the following optional entries:
      :scope       The search scope, can be :base :one or :sub,
                   defaults to :sub
      :filter      A string describing the search filter,
                   defaults to \"(objectclass=*)\"
      :attributes  A collection of the attributes to return,
                   defaults to all user attributes
      :queue-size  The size of the internal queue used to store results before
                   they are passed to the function, the default is 100"
  ([connection base f]
   (search! connection base nil f))
  ([connection base options f]
   (let [queue-size (or (:queue-size options) 100)]
       (search-results! connection
                        (search-criteria base options)
                        queue-size
                        f))))

