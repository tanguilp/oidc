defmodule OIDC.MixProject do
  use Mix.Project

  def project do
    [
      app: :oidc,
      description: "Convenience functions to work with OpenID Connect",
      version: "0.1.0",
      elixir: "~> 1.9",
      elixirc_paths: elixirc_paths(Mix.env()),
      docs: [
        main: "readme",
        extras: ["README.md"]
      ],
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      source_url: "https://github.com/tanguilp/oidc"
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:jason, "~> 1.1"},
      {:jose_utils, "~> 0.1.0"},
      {:jwks_uri_updater, "~> 1.0"},
      {:oauth2_metadata_updater, "~> 1.0"},
      {:oauth2_utils, "~> 0.1.0"},
      {:tesla_oauth2_client_auth, "~> 0.1.0"},
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def package() do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/tanguilp/oidc"}
    ]
  end
end
