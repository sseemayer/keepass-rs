{
  inputs = {
    nixpkgs = {
      url = "github:nixos/nixpkgs";
    };
    flake-utils = {
      url = "github:numtide/flake-utils";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }: (
    flake-utils.lib.eachDefaultSystem (
      system: (
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in {
          devShell = pkgs.mkShell {
            buildInputs = with pkgs; [
              cargo
              rustc
              rustfmt
              rust-analyzer
              cargo-tarpaulin
              cargo-msrv
              cargo-hack
            ];
          };
        }
      )
    )
  );
}
