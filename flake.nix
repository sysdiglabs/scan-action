{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };
  outputs =
    {
      self,
      nixpkgs,
      utils,
    }:
    utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };
      in
      {
        devShells.default =
          with pkgs;
          mkShell {
            buildInputs = [
              just
              coreutils
              gnused
              typescript
              nodejs_24
              pinact
              prek
              typescript-language-server
              eslint
            ];

            shellHook = ''
              prek install --overwrite
            '';
          };

        formatter = pkgs.alejandra;
      }
    );
}
