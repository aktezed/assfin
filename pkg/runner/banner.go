package runner

import (
	"github.com/projectdiscovery/gologger"
)

const version = "v1.0.9"

const banner = `
                  ____ _       
   ____ _________/ __/(_)___   
  / __ ` + "`" + `/ ___/ ___/ /_ / / __ \  
 / /_/ (__  |__  ) __// / / / /  
 \__,_/____/____/_/  /_/_/ /_/   
`

// showBanner prints the application banner.
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\taktezed/assfin %s\n\n", version)
}
