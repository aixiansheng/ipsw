/*
Copyright © 2019 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"io"
	"io/ioutil"
	"os"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/spf13/cobra"
)

func init() {
	kernelcacheCmd.AddCommand(extractKextCmd)
	extractKextCmd.PersistentFlags().Bool("all", false, "extract all kexts")
	extractKextCmd.PersistentFlags().Bool("analyze", false, "analyze all of the kexts (new kernel cache format only)")
}

// extractKextCmd represents the dumpKext command
var extractKextCmd = &cobra.Command{
	Use:   "extractKext",
	Short: "Extract a kext from a kernelcache",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		all, _ := cmd.Flags().GetBool("all")
		analyze, _ := cmd.Flags().GetBool("analyze")

		if all || analyze {
			kc, err := kernelcache.NewKernelCache(args[0])
			if err != nil {
				return err
			}

			defer kc.Close()

			if !Verbose {
				log.SetLevel(log.WarnLevel)
			}

			kextAnalyzer := kc.NewKextAnalyzer()
			err = kc.ForeachKext(func(kextName string, kextMachO * macho.File, offset int64) error {
				if kext, err := kc.ExtractKext(kextName, kextMachO); err == nil {
					kextAnalyzer.AnalyzeKext(kext)

					fh := ioutil.Discard
					if !analyze {
						fh, err := os.Create(kextName)
						if err != nil {
							return err
						}

						defer fh.Close()
					}

					_, err = io.Copy(fh, kext)
					return err
				}

				return nil
			})

			if err != nil {
				return err
			}

			kextAnalyzer.DisplayResults()

			return nil
		} else {
			kc, err := kernelcache.NewKernelCache(args[0])
			if err != nil {
				return err
			}

			defer kc.Close()

			kext, err := kc.ExtractKextWithName(args[1])
			if err != nil {
				return err
			}

			fh, err := os.Create(args[1])
			if err != nil {
				return err
			}

			defer fh.Close()

			_, err = io.Copy(fh, kext)
			return err
		}
	},
}
