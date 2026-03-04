cask "credctl" do
  version "0.1.0"
  sha256 "REPLACE_AFTER_FIRST_RELEASE"

  url "https://github.com/matzhouse/credctl/releases/download/v#{version}/credctl-#{version}-darwin-arm64.tar.gz"
  name "credctl"
  desc "Machine identity management with macOS Secure Enclave"
  homepage "https://github.com/matzhouse/credctl"

  depends_on macos: ">= :ventura"
  depends_on arch: :arm64

  app "credctl.app"
  binary "#{appdir}/credctl.app/Contents/MacOS/credctl"

  zap trash: "~/.credctl"
end
