"""Actual generated CMSG -> vault -> sealed popup -> original server session."""
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait


def run_login(driver):
    driver.get('https://alpha.example.test/__member-fixture.html')
    result = driver.execute_async_script('''
      const done = arguments[0];
      (async () => {
        const {createConfiguredVaultClient} = await import('/browser.js');
        window.originalClient = await createConfiguredVaultClient();
        const state = await originalClient.call('login.start', {});
        done(state.state === 'pending');
      })().catch(() => done(false));
    ''')
    if result is not True:
        raise RuntimeError('original browser login did not start')
    wait = WebDriverWait(driver, 30)
    member = driver.current_window_handle
    driver.switch_to.frame(driver.find_element(By.CSS_SELECTOR, '[data-cmsg-vault]'))
    wait.until(lambda d: d.find_element(By.ID, 'continue').is_enabled())
    driver.find_element(By.ID, 'continue').click()
    driver.switch_to.default_content()
    wait.until(lambda d: len(d.window_handles) == 2)
    driver.switch_to.window(next(h for h in driver.window_handles if h != member))
    wait.until(lambda d: d.execute_script('return document.body.dataset.state') == 'ready')
    if not driver.execute_script("return opener === null && location.hash === '' && isSecureContext"):
        raise RuntimeError('popup isolation or launch consumption refused')
    driver.execute_cdp_cmd('WebAuthn.enable', {})
    driver.execute_cdp_cmd('WebAuthn.addVirtualAuthenticator', {'options': {
        'protocol':'ctap2', 'ctap2Version':'ctap2_1', 'transport':'internal',
        'hasResidentKey':True, 'hasUserVerification':True, 'isUserVerified':True,
        'automaticPresenceSimulation':True, 'hasPrf':True,
    }})
    driver.find_element(By.ID, 'register').click()
    wait.until(lambda d: d.execute_script('return document.body.dataset.registered') == 'true')
    driver.find_element(By.ID, 'continue').click()
    wait.until(lambda d: d.execute_script('return document.body.dataset.state') == 'handed_back')
    driver.close()
    driver.switch_to.window(member)
    result = driver.execute_async_script('''
      const done = arguments[0];
      (async () => {
        for (let attempt=0;attempt<100;attempt++) {
          const state = await originalClient.call('login.poll', {});
          if (state.state === 'authenticated_pending_custody') {
            const lobby = await originalClient.call('foyer.lobby', {});
            if (typeof lobby.member_id !== 'string') throw new Error('real membership missing');
            const status = await originalClient.call('runtime.status', {});
            if (status.preload !== 'unavailable') throw new Error('fabricated custody');
            await originalClient.dispose(); done(true); return;
          }
          if (state.state !== 'pending') throw new Error('unexpected login state');
          await new Promise(resolve => setTimeout(resolve,50));
        }
        done(false);
      })().catch(() => done(false));
    ''')
    if result is not True:
        raise RuntimeError('actual CMSG browser session or custody boundary refused')
    # Fresh real owner: cancel before any popup, then start a new generation.
    result = driver.execute_async_script('''
      const done = arguments[0];
      (async () => {
        const {createConfiguredVaultClient} = await import('/browser.js');
        const owner = await createConfiguredVaultClient();
        for (let index=0;index<2;index++) {
          if ((await owner.call('login.start',{})).state !== 'pending') throw new Error('start');
          if ((await owner.call('login.cancel',{})).state !== 'cancelled') throw new Error('cancel');
        }
        await owner.dispose(); done(!document.querySelector('[data-cmsg-vault]'));
      })().catch(() => done(false));
    ''')
    if result is not True:
        raise RuntimeError('actual cancelled owner did not release and drain')
