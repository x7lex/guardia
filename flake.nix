{
  description = "Dev Flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    treefmt.url = "github:numtide/treefmt-nix";
    systems.url = "github:nix-systems/default";
  };
  outputs =
    {
      self,
      nixpkgs,
      treefmt,
      systems,
    }:
    let
      forAllSystems =
        f: nixpkgs.lib.genAttrs (import systems) (system: f nixpkgs.legacyPackages.${system});
    in
    {
      formatter = forAllSystems (
        pkgs:
        (treefmt.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs.nixfmt.enable = true;
          programs.ruff = {
            enable = true;
            format = true;
          };
          programs.prettier.enable = true;
        }).config.build.wrapper
      );
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.python3.withPackages (ps: [
              ps.capstone
              ps.lief
              ps.fastapi
              ps.websockets
              ps.uvicorn
            ]))
          ];
        };
      });
    };
}
