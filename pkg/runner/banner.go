package runner

import (
	"github.com/projectdiscovery/gologger"
)

const version = "1.0.0"

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
	gologger.Print().Msgf("\t\tdzaki/assfin %s\n\n", version)
}
