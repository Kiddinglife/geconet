GECO XML
========


Request Content Types
---------------------

The following :http:header:`Content-Type` are parsed by
:py:class:`~engines.shared.slots.gecoxml.parser.GECOXMLParser()`:

.. _application/vnd.geco.slots.spin-v1+xml:

- application/vnd.geco.slots.spin-v1+xml

.. _application/vnd.geco.slots.freespin-v1+xml:

- application/vnd.geco.slots.freespin-v1+xml
.. _application/vnd.geco.slots.gamble-v1+xml:

- application/vnd.geco.slots.gamble-v1+xml

.. _application/vnd.geco.slots.feature_accept-v1+xml:

- application/vnd.geco.slots.feature_accept-v1+xml

.. _application/vnd.geco.slots.feature_replay-v1+xml:

- application/vnd.geco.slots.feature_replay-v1+xml

.. _application/vnd.geco.slots.feature_mystery-v1+xml:

- application/vnd.geco.slots.feature_mystery-v1+xml


.. autoclass:: engines.shared.slots.gecoxml.parser.GECOXMLParser()
   :members:


Response Content Types
----------------------

.. _application/vnd.geco.game-v1+xml:

:mimetype:`application/vnd.geco.game-v1+xml`
  Primary Resource: :doc:`resource-game`

.. _application/vnd.geco.gameplay-v1+xml:

:mimetype:`application/vnd.geco.gameplay-v1+xml`
  Primary Resource: :doc:`resource-gameplay`

.. _application/vnd.geco.error-v1+xml:

:mimetype:`application/vnd.geco.error-v1+xml`


Known Action Names
------------------

.. glossary::

  Spin
    The main slot spin.

  FreeSpin
    A prize in slot games where you can play a spin without paying stake.

  Gamble
    A zero-sum bonus game where player can choose to risk their winning for
    a proportionally larger reward.

  FeatureAccept
  FeatureReplay
  FeatureMystery
    Time gamble special features.
