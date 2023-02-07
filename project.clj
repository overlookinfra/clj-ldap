(defproject puppetlabs/clj-ldap "0.4.0-SNAPSHOT"
  :description "Clojure ldap client (Puppet Labs's fork)."
  :url "https://github.com/puppetlabs/clj-ldap"
  :dependencies [[org.clojure/clojure "1.10.1"]
                 [com.unboundid/unboundid-ldapsdk "6.0.7"]]
  :source-paths ["src/clojure"]
  :java-source-paths ["src/java"]
  :profiles {:dev {:dependencies [[jline "0.9.94"]
                                  [org.apache.directory.server/apacheds-all "1.5.7"
                                   ;; This dependency causes the classpath to contain two copies of the schema,
                                   ;; which prevents the test Directory Service from starting
                                   :exclusions [org.apache.directory.shared/shared-ldap-schema]]
                                  [fs "1.1.2"]
                                  [org.slf4j/slf4j-simple "1.5.6"]]}}

  :deploy-repositories [["releases" {:url "https://clojars.org/repo"
                                     :username :env/clojars_jenkins_username
                                     :password :env/clojars_jenkins_password
                                     :sign-releases false}]]
  :license {:name "Eclipse Public License - v 1.0"
            :url "http://www.eclipse.org/legal/epl-v10.html"
            :distribution :repo
            :comments "same as Clojure"})
