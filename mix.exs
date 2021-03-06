defmodule ACL.Mixfile do
  use Mix.Project

  def project do
    [app: :acl_ex,
     version: "0.0.1",
     elixir: "~> 1.0",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps]
  end

  def application do
    [applications: [:logger, :linear_ex]]
  end

  defp deps do
    [{:linear_ex, git: "https://github.com/jonnystorm/linear-elixir.git"}]
  end
end
