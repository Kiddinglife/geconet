Welcome to GECO's documentation!
================================

Contents:

.. toctree::
   :maxdepth: 2
   :glob:

   mediatypes
   resources
   engine-state-machine
   blackjack


TODO: Merge the following with the rest of the docs

Media Types
-----------

The GECO JSON media type and GECO XML media type are essentially two
representations of the same concept. The only significant differences are the
syntax, and how forms are expressed. The semantic of all operations between the
representation formats are the same.

There are three basic type of resources:

Resources
---------

Game Definition Resource
^^^^^^^^^^^^^^^^^^^^^^^^

Properties
``````````

- Game detail: game name, host name, interface name, session currency
- Player detail: balance and balance currency
- Game parameters and definition (varies with each game)

Relations
`````````

- latest-gameplay: link to a Gameplay Resource. Link available when the player
  previously played on the hostgame.
- new-game: link to start a new gameplay. Response contains a representation of
  the Gameplay Resource that has just been started. Link available only when it
  is possible to create a new game. Client should look into the
  latest-gameplay's new-game link and only fallback here when they fail to find
  one there.


Gameplay Resource
^^^^^^^^^^^^^^^^^

Properties
``````````

- Game detail: game name, host name, interface name, session currency
- Player detail: balance and balance currency
- Gameplay status: can be OPEN, FINISHED, CLOSED (an additional status FAILED
  is used internally by GECO, but client should never encounter one)
- Gameplay data (varies with each game)

Relations
`````````

- host-game: link to the Game Definition Resource for the current gameplay
- player-client-state and player-client-state-save: link to player-scoped
  storage Binary Resource
- gameplay-client-state and gameplay-client-state-save: link to gameplay-scoped
  storage Binary Resource
- new-game: link to start a new gameplay. Response contains a representation of
  the Gameplay Resource that has just been started. Link available only when
  this is the latest-gameplay and it is possible to create a new game.
- option: link to continue on the current gameplay. Response contains a
  representation of the latest state of the Gameplay Resource. Link available
  only when the option is available (varies by game rules)


Binary Resource
^^^^^^^^^^^^^^^

The client storages is freeform binary format.

Clients need to take care that the format used is compatible between different
versions of the game that uses the same hostgame, so if a Flash-based client
stores client state in XML and a HTML5 JSON client also share the same
hostgame, they must be able to read and write in mutually compatible format.

Relations
`````````

- None

General-purpose Relations
-------------------------

- self: link to retrieve the current resource


Forms
-----

Forms are part of the links and they vary with each game. GECO XML use XForm;
in GECO JSON use use a custom form schema (this is subject to change if we
found a suitable standard for representing JSON forms). The form defines the
initial values and a set of data binds that defines which parameters are
required to do the request. The set of possible bind names varies with each
game.


HTTP Headers
------------

Refer to RFC2616 for usages of standard HTTP status code, headers, etc. For
custom HTTP headers, refer to Compatibility Notes and Workarounds in the
Debugging Mode.


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

