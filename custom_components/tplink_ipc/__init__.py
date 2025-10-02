"""The TP-Link IPC Camera integration."""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .api import TPLinkIPCApiClient
from .const import DOMAIN, PLATFORMS
from .models import TPLinkCameraData
from .talkback import TPLinkTalkbackPlayer


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up TP-Link IPC Camera from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    host = entry.data[CONF_HOST]
    username = entry.data[CONF_USERNAME]
    password = entry.data[CONF_PASSWORD]

    # Create both API and Talkback clients
    api_client = TPLinkIPCApiClient(
        host=host,
        username=username,
        password=password,
    )
    
    talkback_client = TPLinkTalkbackPlayer(
        ip=host,
        user=username,
        password=password,
    )

    try:
        await hass.async_add_executor_job(api_client.sync_time)
    except Exception as e:
        pass
        

    # Store clients in a data container
    camera_data = TPLinkCameraData(
        api_client=api_client, talkback_client=talkback_client
    )
    hass.data[DOMAIN][entry.entry_id] = camera_data

    # Forward setup to platforms (switch and media_player)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok