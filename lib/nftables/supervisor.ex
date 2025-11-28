defmodule NFTables.Supervisor do
  @moduledoc """
  Supervisor for the NFTex JSON port process.

  This supervisor ensures the JSON port process is restarted if it crashes,
  providing fault tolerance for the nftables interface.

  ## Usage

      children = [
        {NFTables.Supervisor, name: NFTex}
      ]

      Supervisor.start_link(children, strategy: :one_for_one)

  Then you can use the registered name:

      alias NFTables.Builder

      Builder.new()
      |> Builder.add(table: "filter", family: :inet)
      |> Builder.execute(NFTex)
  """

  use Supervisor

  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts \\ []) do
    Supervisor.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    port_name = opts[:name] || NFTex

    children = [
      {NFTables.Port, [name: port_name]}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end
