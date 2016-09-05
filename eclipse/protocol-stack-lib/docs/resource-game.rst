Game Definition Resource
========================

Game Definition Resource


Properties
----------

Game Detail
  name
    The name of the game
  
  host
    The name of the host
  
  interface
    The name of the interface
  
  session currency
    The currency of the current game session

Player Detail
  balance and balance currency

Game Parameters (varies by game)

Game Definition (varies by game)


Link Relations
--------------

self
  link to the current resource

  .. http:get:: <self> 
  
     retrieves the latest host game definition

  .. http:post:: <self>

     start a new gameplay

new-game
  link to start a new gameplay, only exist when starting a new gameplay is
  possible

  See also, gameplay's new-game link relation.

latest-gameplay
  link to the last gameplay played by the player on the Host Game.
  
  Type: Gameplay Resource.
  Visibility: only when the player previously played on the Host Game.

  .. http:get:: <latest-gameplay>

     retrieve the last gameplay played by the current player on the given host game

  .. http:post:: <latest-gameplay>

     used to recover the last gameplay when the latest-gameplay's status=FAILED



Class
-----

.. autoclass:: web.views.HostGame
   :members: get, post
