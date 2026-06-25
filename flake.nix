{
  description = "Multi-target network scan lab";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forEachSystem = f:
        builtins.listToAttrs (map
          (system: {
            name = system;
            value = f system;
          })
          systems);
      mkPkgs = system: import nixpkgs { inherit system; };
      mkPkgsUnfree = system: import nixpkgs {
        inherit system;
        config.allowUnfree = true;
      };
    in
    {
      devShells = forEachSystem (system:
        let
          pkgs = mkPkgs system;
          pythonEnv = pkgs.python312.withPackages (ps: with ps; [
            openai
            pyyaml
            xmltodict
          ]);
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              just
              jq
              yq-go
              git
              podman
              podman-compose
              docker-compose
              pythonEnv
            ];
            shellHook = ''
              export PATH="${pythonEnv}/bin:$PATH"
            '';
          };
        });

      packages = forEachSystem (system:
        let
          pkgs = mkPkgsUnfree system;
        in
        {
          llama-cpp-cuda = pkgs.llama-cpp.override {
            cudaSupport = true;
            cudaPackages = pkgs.cudaPackages;
          };
        });

      formatter = forEachSystem (system:
        let
          pkgs = mkPkgs system;
        in
        pkgs.nixfmt-rfc-style);
    };
}
