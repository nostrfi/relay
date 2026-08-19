export default defineAppConfig({
  ui: {
    colors: {
      primary: 'violet',
      neutral: 'slate'
    },

    /*
     * A dashboard panel's body is a flex column, so its children are flex
     * items and shrink to fit the viewport rather than making the panel
     * scroll. Every card on a page taller than the window was therefore
     * clipped — tile values cut off, table rows sliced in half — while the
     * markup, the tests and the server-rendered HTML were all perfectly
     * correct (nostrfi/workspace#39, found by screenshotting the page).
     *
     * Set here rather than per page so no future page has to remember it.
     */
    dashboardPanel: {
      slots: {
        body: '[&>*]:shrink-0'
      }
    }
  }
})
