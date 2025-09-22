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
              typescript
              nodejs_20
              pre-commit
            ]
            ++ (with nodePackages; [
              typescript-language-server
              eslint
            ]);

            shellHook = ''
              pre-commit install
            '';
          };

        formatter = pkgs.alejandra;
      }
    );
}
