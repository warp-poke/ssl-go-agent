package models

// SSLLabsResponse simplified response
type SSLLabsResponse struct {
	Host            string `json:"host"`
	Port            int    `json:"port"`
	Protocol        string `json:"protocol"`
	IsPublic        bool   `json:"isPublic"`
	Status          string `json:"status"`
	StartTime       int64  `json:"startTime"`
	TestTime        int64  `json:"testTime"`
	EngineVersion   string `json:"engineVersion"`
	CriteriaVersion string `json:"criteriaVersion"`
	Endpoints       []struct {
		IPAddress         string `json:"ipAddress"`
		ServerName        string `json:"serverName"`
		StatusMessage     string `json:"statusMessage"`
		Grade             string `json:"grade"`
		GradeTrustIgnored string `json:"gradeTrustIgnored"`
		HasWarnings       bool   `json:"hasWarnings"`
		IsExceptional     bool   `json:"isExceptional"`
		Progress          int    `json:"progress"`
		Duration          int    `json:"duration"`
		Eta               int    `json:"eta"`
		Delegation        int    `json:"delegation"`
		Details           struct {
			HostStartTime int64 `json:"hostStartTime"`
			Key           struct {
				Size       int    `json:"size"`
				Alg        string `json:"alg"`
				DebianFlaw bool   `json:"debianFlaw"`
				Strength   int    `json:"strength"`
			} `json:"key"`
			Cert struct {
				Subject              string   `json:"subject"`
				CommonNames          []string `json:"commonNames"`
				AltNames             []string `json:"altNames"`
				NotBefore            uint64   `json:"notBefore"`
				NotAfter             uint64   `json:"notAfter"`
				IssuerSubject        string   `json:"issuerSubject"`
				IssuerLabel          string   `json:"issuerLabel"`
				SigAlg               string   `json:"sigAlg"`
				RevocationInfo       int      `json:"revocationInfo"`
				CrlURIs              []string `json:"crlURIs"`
				OcspURIs             []string `json:"ocspURIs"`
				RevocationStatus     int      `json:"revocationStatus"`
				CrlRevocationStatus  int      `json:"crlRevocationStatus"`
				OcspRevocationStatus int      `json:"ocspRevocationStatus"`
				Sgc                  int      `json:"sgc"`
				ValidationType       string   `json:"validationType"`
				Issues               int      `json:"issues"`
				Sct                  bool     `json:"sct"`
				MustStaple           int      `json:"mustStaple"`
				Sha1Hash             string   `json:"sha1Hash"`
				PinSha256            string   `json:"pinSha256"`
			} `json:"cert"`
			Chain struct {
				Certs []struct {
					Subject              string `json:"subject"`
					Label                string `json:"label"`
					NotBefore            int64  `json:"notBefore"`
					NotAfter             int64  `json:"notAfter"`
					IssuerSubject        string `json:"issuerSubject"`
					IssuerLabel          string `json:"issuerLabel"`
					SigAlg               string `json:"sigAlg"`
					Issues               int    `json:"issues"`
					KeyAlg               string `json:"keyAlg"`
					KeySize              int    `json:"keySize"`
					KeyStrength          int    `json:"keyStrength"`
					RevocationStatus     int    `json:"revocationStatus"`
					CrlRevocationStatus  int    `json:"crlRevocationStatus"`
					OcspRevocationStatus int    `json:"ocspRevocationStatus"`
					Sha1Hash             string `json:"sha1Hash"`
					PinSha256            string `json:"pinSha256"`
					Raw                  string `json:"raw"`
				} `json:"certs"`
				Issues int `json:"issues"`
			} `json:"chain"`
			Protocols []struct {
				ID      int    `json:"id"`
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"protocols"`
			Suites struct {
				List []struct {
					ID             int    `json:"id"`
					Name           string `json:"name"`
					CipherStrength int    `json:"cipherStrength"`
					EcdhBits       int    `json:"ecdhBits,omitempty"`
					EcdhStrength   int    `json:"ecdhStrength,omitempty"`
					DhStrength     int    `json:"dhStrength,omitempty"`
					DhP            int    `json:"dhP,omitempty"`
					DhG            int    `json:"dhG,omitempty"`
					DhYs           int    `json:"dhYs,omitempty"`
				} `json:"list"`
				Preference bool `json:"preference"`
			} `json:"suites"`
			PrefixDelegation    bool   `json:"prefixDelegation"`
			NonPrefixDelegation bool   `json:"nonPrefixDelegation"`
			VulnBeast           bool   `json:"vulnBeast"`
			RenegSupport        int    `json:"renegSupport"`
			StsStatus           string `json:"stsStatus"`
			StsResponseHeader   string `json:"stsResponseHeader"`
			StsSubdomains       bool   `json:"stsSubdomains"`
			StsPreload          bool   `json:"stsPreload"`
			SessionResumption   int    `json:"sessionResumption"`
			CompressionMethods  int    `json:"compressionMethods"`
			SupportsNpn         bool   `json:"supportsNpn"`
			SupportsAlpn        bool   `json:"supportsAlpn"`
			SessionTickets      int    `json:"sessionTickets"`
			OcspStapling        bool   `json:"ocspStapling"`
			SniRequired         bool   `json:"sniRequired"`
			HTTPStatusCode      int    `json:"httpStatusCode"`
			HTTPForwarding      string `json:"httpForwarding"`
			SupportsRc4         bool   `json:"supportsRc4"`
			Rc4WithModern       bool   `json:"rc4WithModern"`
			Rc4Only             bool   `json:"rc4Only"`
			ForwardSecrecy      int    `json:"forwardSecrecy"`
			ProtocolIntolerance int    `json:"protocolIntolerance"`
			MiscIntolerance     int    `json:"miscIntolerance"`
			Sims                struct {
				Results []struct {
					Client struct {
						ID          int    `json:"id"`
						Name        string `json:"name"`
						Version     string `json:"version"`
						IsReference bool   `json:"isReference"`
					} `json:"client"`
					ErrorCode  int    `json:"errorCode"`
					Attempts   int    `json:"attempts"`
					ProtocolID int    `json:"protocolId,omitempty"`
					SuiteID    int    `json:"suiteId,omitempty"`
					KxInfo     string `json:"kxInfo,omitempty"`
				} `json:"results"`
			} `json:"sims"`
			Heartbleed          bool     `json:"heartbleed"`
			Heartbeat           bool     `json:"heartbeat"`
			OpenSslCcs          int      `json:"openSslCcs"`
			OpenSSLLuckyMinus20 int      `json:"openSSLLuckyMinus20"`
			Poodle              bool     `json:"poodle"`
			PoodleTLS           int      `json:"poodleTls"`
			FallbackScsv        bool     `json:"fallbackScsv"`
			Freak               bool     `json:"freak"`
			HasSct              int      `json:"hasSct"`
			DhPrimes            []string `json:"dhPrimes"`
			DhUsesKnownPrimes   int      `json:"dhUsesKnownPrimes"`
			DhYsReuse           bool     `json:"dhYsReuse"`
			Logjam              bool     `json:"logjam"`
			HstsPolicy          struct {
				LONGMAXAGE int    `json:"LONG_MAX_AGE"`
				Status     string `json:"status"`
				Directives struct {
				} `json:"directives"`
			} `json:"hstsPolicy"`
			HstsPreloads []struct {
				Source     string `json:"source"`
				Hostname   string `json:"hostname"`
				Status     string `json:"status"`
				SourceTime int64  `json:"sourceTime"`
			} `json:"hstsPreloads"`
			HpkpPolicy struct {
				Status      string        `json:"status"`
				Pins        []interface{} `json:"pins"`
				MatchedPins []interface{} `json:"matchedPins"`
				Directives  []interface{} `json:"directives"`
			} `json:"hpkpPolicy"`
			HpkpRoPolicy struct {
				Status      string        `json:"status"`
				Pins        []interface{} `json:"pins"`
				MatchedPins []interface{} `json:"matchedPins"`
				Directives  []interface{} `json:"directives"`
			} `json:"hpkpRoPolicy"`
			DrownHosts      []interface{} `json:"drownHosts"`
			DrownErrors     bool          `json:"drownErrors"`
			DrownVulnerable bool          `json:"drownVulnerable"`
		} `json:"details"`
	} `json:"endpoints"`
}
