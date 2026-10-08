; Lab de escritorio: un acceso directo por jugador. Cada uno abre la mesa con la
; cuenta N del nodo Hardhat y su propia carpeta de datos (--jugador N), asi dos
; jugadores pueden jugar en el mismo PC sin compartir vault ni clave K.

!macro NSIS_HOOK_POSTINSTALL
  CreateShortCut "$SMPROGRAMS\${PRODUCTNAME} - Jugador 0.lnk" "$INSTDIR\${MAINBINARYNAME}.exe" "--jugador 0"
  CreateShortCut "$SMPROGRAMS\${PRODUCTNAME} - Jugador 1.lnk" "$INSTDIR\${MAINBINARYNAME}.exe" "--jugador 1"
  CreateShortCut "$DESKTOP\${PRODUCTNAME} - Jugador 0.lnk" "$INSTDIR\${MAINBINARYNAME}.exe" "--jugador 0"
  CreateShortCut "$DESKTOP\${PRODUCTNAME} - Jugador 1.lnk" "$INSTDIR\${MAINBINARYNAME}.exe" "--jugador 1"
  ; Sin --jugador la mesa del lab no tiene cuenta: fuera el acceso generico.
  Delete "$SMPROGRAMS\${PRODUCTNAME}.lnk"
  Delete "$DESKTOP\${PRODUCTNAME}.lnk"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  Delete "$SMPROGRAMS\${PRODUCTNAME} - Jugador 0.lnk"
  Delete "$SMPROGRAMS\${PRODUCTNAME} - Jugador 1.lnk"
  Delete "$DESKTOP\${PRODUCTNAME} - Jugador 0.lnk"
  Delete "$DESKTOP\${PRODUCTNAME} - Jugador 1.lnk"
!macroend
