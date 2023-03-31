# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import os
import unittest
import pytest
import json
import deepdiff
import docker

from azext_confcom.security_policy import (
    OutputType,
    load_policy_from_image_name,
)
import azext_confcom.config as config

TEST_DIR = os.path.abspath(os.path.join(os.path.abspath(__file__), ".."))


# @unittest.skip("not in use")
@pytest.mark.run(order=1)
class PolicyGeneratingImage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with load_policy_from_image_name("python:3.6.14-slim-buster") as aci_policy:
            aci_policy.populate_policy_content_for_all_images(individual_image=True)
            cls.aci_policy = aci_policy

    def test_image_policy(self):
        expected_policy = "cGFja2FnZSBwb2xpY3kKCmltcG9ydCBmdXR1cmUua2V5d29yZHMuZXZlcnkKaW1wb3J0IGZ1dHVyZS5rZXl3b3Jkcy5pbgoKYXBpX3ZlcnNpb24gOj0gIjAuMTAuMCIKZnJhbWV3b3JrX3ZlcnNpb24gOj0gIjAuMi4zIgoKZnJhZ21lbnRzIDo9IFsKICB7CiAgICAiZmVlZCI6ICJtY3IubWljcm9zb2Z0LmNvbS9hY2kvYWNpLWNjLWluZnJhLWZyYWdtZW50IiwKICAgICJpbmNsdWRlcyI6IFsKICAgICAgImNvbnRhaW5lcnMiCiAgICBdLAogICAgImlzc3VlciI6ICJkaWQ6eDUwOTowOnNoYTI1NjpJX19pdUwyNW9YRVZGZFRQX2FCTHhfZVQxUlBIYkNRX0VDQlFmWVpwdDlzOjpla3U6MS4zLjYuMS40LjEuMzExLjc2LjU5LjEuMyIsCiAgICAibWluaW11bV9zdm4iOiAiMS4wLjAiCiAgfQpdCgpjb250YWluZXJzIDo9IFt7ImFsbG93X2VsZXZhdGVkIjp0cnVlLCJhbGxvd19zdGRpb19hY2Nlc3MiOnRydWUsImNhcGFiaWxpdGllcyI6eyJhbWJpZW50IjpbXSwiYm91bmRpbmciOlsiQ0FQX0FVRElUX1dSSVRFIiwiQ0FQX0NIT1dOIiwiQ0FQX0RBQ19PVkVSUklERSIsIkNBUF9GT1dORVIiLCJDQVBfRlNFVElEIiwiQ0FQX0tJTEwiLCJDQVBfTUtOT0QiLCJDQVBfTkVUX0JJTkRfU0VSVklDRSIsIkNBUF9ORVRfUkFXIiwiQ0FQX1NFVEZDQVAiLCJDQVBfU0VUR0lEIiwiQ0FQX1NFVFBDQVAiLCJDQVBfU0VUVUlEIiwiQ0FQX1NZU19DSFJPT1QiXSwiZWZmZWN0aXZlIjpbIkNBUF9BVURJVF9XUklURSIsIkNBUF9DSE9XTiIsIkNBUF9EQUNfT1ZFUlJJREUiLCJDQVBfRk9XTkVSIiwiQ0FQX0ZTRVRJRCIsIkNBUF9LSUxMIiwiQ0FQX01LTk9EIiwiQ0FQX05FVF9CSU5EX1NFUlZJQ0UiLCJDQVBfTkVUX1JBVyIsIkNBUF9TRVRGQ0FQIiwiQ0FQX1NFVEdJRCIsIkNBUF9TRVRQQ0FQIiwiQ0FQX1NFVFVJRCIsIkNBUF9TWVNfQ0hST09UIl0sImluaGVyaXRhYmxlIjpbXSwicGVybWl0dGVkIjpbIkNBUF9BVURJVF9XUklURSIsIkNBUF9DSE9XTiIsIkNBUF9EQUNfT1ZFUlJJREUiLCJDQVBfRk9XTkVSIiwiQ0FQX0ZTRVRJRCIsIkNBUF9LSUxMIiwiQ0FQX01LTk9EIiwiQ0FQX05FVF9CSU5EX1NFUlZJQ0UiLCJDQVBfTkVUX1JBVyIsIkNBUF9TRVRGQ0FQIiwiQ0FQX1NFVEdJRCIsIkNBUF9TRVRQQ0FQIiwiQ0FQX1NFVFVJRCIsIkNBUF9TWVNfQ0hST09UIl19LCJjb21tYW5kIjpbInB5dGhvbjMiXSwiZW52X3J1bGVzIjpbeyJwYXR0ZXJuIjoiUEFUSD0vdXNyL2xvY2FsL2JpbjovdXNyL2xvY2FsL3NiaW46L3Vzci9sb2NhbC9iaW46L3Vzci9zYmluOi91c3IvYmluOi9zYmluOi9iaW4iLCJyZXF1aXJlZCI6ZmFsc2UsInN0cmF0ZWd5Ijoic3RyaW5nIn0seyJwYXR0ZXJuIjoiTEFORz1DLlVURi04IiwicmVxdWlyZWQiOmZhbHNlLCJzdHJhdGVneSI6InN0cmluZyJ9LHsicGF0dGVybiI6IkdQR19LRVk9MEQ5NkRGNEQ0MTEwRTVDNDNGQkZCMTdGMkQzNDdFQTZBQTY1NDIxRCIsInJlcXVpcmVkIjpmYWxzZSwic3RyYXRlZ3kiOiJzdHJpbmcifSx7InBhdHRlcm4iOiJQWVRIT05fVkVSU0lPTj0zLjYuMTQiLCJyZXF1aXJlZCI6ZmFsc2UsInN0cmF0ZWd5Ijoic3RyaW5nIn0seyJwYXR0ZXJuIjoiUFlUSE9OX1BJUF9WRVJTSU9OPTIxLjIuNCIsInJlcXVpcmVkIjpmYWxzZSwic3RyYXRlZ3kiOiJzdHJpbmcifSx7InBhdHRlcm4iOiJQWVRIT05fR0VUX1BJUF9VUkw9aHR0cHM6Ly9naXRodWIuY29tL3B5cGEvZ2V0LXBpcC9yYXcvYzIwYjBjZmQ2NDNjZDRhMTkyNDZjY2YyMDRlMjk5N2FmNzBmNmIyMS9wdWJsaWMvZ2V0LXBpcC5weSIsInJlcXVpcmVkIjpmYWxzZSwic3RyYXRlZ3kiOiJzdHJpbmcifSx7InBhdHRlcm4iOiJQWVRIT05fR0VUX1BJUF9TSEEyNTY9ZmE2ZjNmYjkzY2NlMjM0Y2Q0ZThkZDJiZWI1NGE1MWFiOWMyNDc2NTNiNTI4NTVhNDhkZDQ0ZTZiMjFmZjI4YiIsInJlcXVpcmVkIjpmYWxzZSwic3RyYXRlZ3kiOiJzdHJpbmcifSx7InBhdHRlcm4iOiJURVJNPXh0ZXJtIiwicmVxdWlyZWQiOmZhbHNlLCJzdHJhdGVneSI6InN0cmluZyJ9LHsicGF0dGVybiI6IigoP2kpRkFCUklDKV8uKz0uKyIsInJlcXVpcmVkIjpmYWxzZSwic3RyYXRlZ3kiOiJyZTIifSx7InBhdHRlcm4iOiJIT1NUTkFNRT0uKyIsInJlcXVpcmVkIjpmYWxzZSwic3RyYXRlZ3kiOiJyZTIifSx7InBhdHRlcm4iOiJUKEUpP01QPS4rIiwicmVxdWlyZWQiOmZhbHNlLCJzdHJhdGVneSI6InJlMiJ9LHsicGF0dGVybiI6IkZhYnJpY1BhY2thZ2VGaWxlTmFtZT0uKyIsInJlcXVpcmVkIjpmYWxzZSwic3RyYXRlZ3kiOiJyZTIifSx7InBhdHRlcm4iOiJIb3N0ZWRTZXJ2aWNlTmFtZT0uKyIsInJlcXVpcmVkIjpmYWxzZSwic3RyYXRlZ3kiOiJyZTIifSx7InBhdHRlcm4iOiJJREVOVElUWV9BUElfVkVSU0lPTj0uKyIsInJlcXVpcmVkIjpmYWxzZSwic3RyYXRlZ3kiOiJyZTIifSx7InBhdHRlcm4iOiJJREVOVElUWV9IRUFERVI9LisiLCJyZXF1aXJlZCI6ZmFsc2UsInN0cmF0ZWd5IjoicmUyIn0seyJwYXR0ZXJuIjoiSURFTlRJVFlfU0VSVkVSX1RIVU1CUFJJTlQ9LisiLCJyZXF1aXJlZCI6ZmFsc2UsInN0cmF0ZWd5IjoicmUyIn0seyJwYXR0ZXJuIjoiYXp1cmVjb250YWluZXJpbnN0YW5jZV9yZXN0YXJ0ZWRfYnk9LisiLCJyZXF1aXJlZCI6ZmFsc2UsInN0cmF0ZWd5IjoicmUyIn1dLCJleGVjX3Byb2Nlc3NlcyI6W10sImlkIjoicHl0aG9uOjMuNi4xNC1zbGltLWJ1c3RlciIsImxheWVycyI6WyIyNTRjYzg1M2RhNjA4MTkwNWM5MTA5YzhiOWQ5OWM5ZmIwOTg3YmExZDg4ZjcyOTA4ODkwM2NmZmI4MGY1NWYxIiwiYTU2OGYxOTAwYmVkNjBhMDY0MWI3NmI5OTFhZDQzMTQ0NmQ5YzNhMzQ0ZDdiMjYxZjEwZGU4ZDhlNzM3NjNhYyIsImM3MGM1MzBlODQyZjY2MjE1YjBiZDk1NTg3NzE1N2JhMjRjMzc5OTMwMzU2N2MzZjU2NzNjNDU2NjNlYTRkMTUiLCIzZTg2YzNjY2YxNjQyYmY1ODRkZTMzYjQ5YzcyNDhmODdlZWNkMGY2ZDhjMDgzNTNkYWEzNmNjN2FkMGE3YjZhIiwiMWU0Njg0ZDhjN2NhYTc0YzY1MjQxNzJiNGQ1YTE1OWExMDg4NzYxM2VkNzBmMThkMGE1NWQwNWIyYWY2MWFjZCJdLCJtb3VudHMiOlt7ImRlc3RpbmF0aW9uIjoiL2V0Yy9yZXNvbHYuY29uZiIsIm9wdGlvbnMiOlsicmJpbmQiLCJyc2hhcmVkIiwicnciXSwic291cmNlIjoic2FuZGJveDovLy90bXAvYXRsYXMvcmVzb2x2Y29uZi8uKyIsInR5cGUiOiJiaW5kIn1dLCJub19uZXdfcHJpdmlsZWdlcyI6ZmFsc2UsInNlY2NvbXBfcHJvZmlsZV9zaGEyNTYiOiIiLCJzaWduYWxzIjpbXSwidXNlciI6eyJncm91cF9pZG5hbWVzIjpbeyJwYXR0ZXJuIjoiIiwic3RyYXRlZ3kiOiJhbnkifV0sInVtYXNrIjoiMDAyMiIsInVzZXJfaWRuYW1lIjp7InBhdHRlcm4iOiIiLCJzdHJhdGVneSI6ImFueSJ9fSwid29ya2luZ19kaXIiOiIvIn0seyJhbGxvd19lbGV2YXRlZCI6ZmFsc2UsImFsbG93X3N0ZGlvX2FjY2VzcyI6dHJ1ZSwiY2FwYWJpbGl0aWVzIjp7ImFtYmllbnQiOltdLCJib3VuZGluZyI6WyJDQVBfQ0hPV04iLCJDQVBfREFDX09WRVJSSURFIiwiQ0FQX0ZTRVRJRCIsIkNBUF9GT1dORVIiLCJDQVBfTUtOT0QiLCJDQVBfTkVUX1JBVyIsIkNBUF9TRVRHSUQiLCJDQVBfU0VUVUlEIiwiQ0FQX1NFVEZDQVAiLCJDQVBfU0VUUENBUCIsIkNBUF9ORVRfQklORF9TRVJWSUNFIiwiQ0FQX1NZU19DSFJPT1QiLCJDQVBfS0lMTCIsIkNBUF9BVURJVF9XUklURSJdLCJlZmZlY3RpdmUiOlsiQ0FQX0NIT1dOIiwiQ0FQX0RBQ19PVkVSUklERSIsIkNBUF9GU0VUSUQiLCJDQVBfRk9XTkVSIiwiQ0FQX01LTk9EIiwiQ0FQX05FVF9SQVciLCJDQVBfU0VUR0lEIiwiQ0FQX1NFVFVJRCIsIkNBUF9TRVRGQ0FQIiwiQ0FQX1NFVFBDQVAiLCJDQVBfTkVUX0JJTkRfU0VSVklDRSIsIkNBUF9TWVNfQ0hST09UIiwiQ0FQX0tJTEwiLCJDQVBfQVVESVRfV1JJVEUiXSwiaW5oZXJpdGFibGUiOltdLCJwZXJtaXR0ZWQiOlsiQ0FQX0NIT1dOIiwiQ0FQX0RBQ19PVkVSUklERSIsIkNBUF9GU0VUSUQiLCJDQVBfRk9XTkVSIiwiQ0FQX01LTk9EIiwiQ0FQX05FVF9SQVciLCJDQVBfU0VUR0lEIiwiQ0FQX1NFVFVJRCIsIkNBUF9TRVRGQ0FQIiwiQ0FQX1NFVFBDQVAiLCJDQVBfTkVUX0JJTkRfU0VSVklDRSIsIkNBUF9TWVNfQ0hST09UIiwiQ0FQX0tJTEwiLCJDQVBfQVVESVRfV1JJVEUiXX0sImNvbW1hbmQiOlsiL3BhdXNlIl0sImVudl9ydWxlcyI6W3sicGF0dGVybiI6IlBBVEg9L3Vzci9sb2NhbC9zYmluOi91c3IvbG9jYWwvYmluOi91c3Ivc2JpbjovdXNyL2Jpbjovc2JpbjovYmluIiwicmVxdWlyZWQiOnRydWUsInN0cmF0ZWd5Ijoic3RyaW5nIn0seyJwYXR0ZXJuIjoiVEVSTT14dGVybSIsInJlcXVpcmVkIjpmYWxzZSwic3RyYXRlZ3kiOiJzdHJpbmcifV0sImV4ZWNfcHJvY2Vzc2VzIjpbXSwibGF5ZXJzIjpbIjE2YjUxNDA1N2EwNmFkNjY1ZjkyYzAyODYzYWNhMDc0ZmQ1OTc2Yzc1NWQyNmJmZjE2MzY1Mjk5MTY5ZTg0MTUiXSwibW91bnRzIjpbXSwibm9fbmV3X3ByaXZpbGVnZXMiOnRydWUsInNlY2NvbXBfcHJvZmlsZV9zaGEyNTYiOiIiLCJzaWduYWxzIjpbXSwidXNlciI6eyJncm91cF9pZG5hbWVzIjpbeyJwYXR0ZXJuIjoiIiwic3RyYXRlZ3kiOiJhbnkifV0sInVtYXNrIjoiMDAyMiIsInVzZXJfaWRuYW1lIjp7InBhdHRlcm4iOiIiLCJzdHJhdGVneSI6ImFueSJ9fSwid29ya2luZ19kaXIiOiIvIn1dCgphbGxvd19wcm9wZXJ0aWVzX2FjY2VzcyA6PSBmYWxzZQphbGxvd19kdW1wX3N0YWNrcyA6PSBmYWxzZQphbGxvd19ydW50aW1lX2xvZ2dpbmcgOj0gZmFsc2UKYWxsb3dfZW52aXJvbm1lbnRfdmFyaWFibGVfZHJvcHBpbmcgOj0gdHJ1ZQphbGxvd191bmVuY3J5cHRlZF9zY3JhdGNoIDo9IGZhbHNlCmFsbG93X2NhcGFiaWxpdHlfZHJvcHBpbmcgOj0gdHJ1ZQoKbW91bnRfZGV2aWNlIDo9IGRhdGEuZnJhbWV3b3JrLm1vdW50X2RldmljZQp1bm1vdW50X2RldmljZSA6PSBkYXRhLmZyYW1ld29yay51bm1vdW50X2RldmljZQptb3VudF9vdmVybGF5IDo9IGRhdGEuZnJhbWV3b3JrLm1vdW50X292ZXJsYXkKdW5tb3VudF9vdmVybGF5IDo9IGRhdGEuZnJhbWV3b3JrLnVubW91bnRfb3ZlcmxheQpjcmVhdGVfY29udGFpbmVyIDo9IGRhdGEuZnJhbWV3b3JrLmNyZWF0ZV9jb250YWluZXIKZXhlY19pbl9jb250YWluZXIgOj0gZGF0YS5mcmFtZXdvcmsuZXhlY19pbl9jb250YWluZXIKZXhlY19leHRlcm5hbCA6PSBkYXRhLmZyYW1ld29yay5leGVjX2V4dGVybmFsCnNodXRkb3duX2NvbnRhaW5lciA6PSBkYXRhLmZyYW1ld29yay5zaHV0ZG93bl9jb250YWluZXIKc2lnbmFsX2NvbnRhaW5lcl9wcm9jZXNzIDo9IGRhdGEuZnJhbWV3b3JrLnNpZ25hbF9jb250YWluZXJfcHJvY2VzcwpwbGFuOV9tb3VudCA6PSBkYXRhLmZyYW1ld29yay5wbGFuOV9tb3VudApwbGFuOV91bm1vdW50IDo9IGRhdGEuZnJhbWV3b3JrLnBsYW45X3VubW91bnQKZ2V0X3Byb3BlcnRpZXMgOj0gZGF0YS5mcmFtZXdvcmsuZ2V0X3Byb3BlcnRpZXMKZHVtcF9zdGFja3MgOj0gZGF0YS5mcmFtZXdvcmsuZHVtcF9zdGFja3MKcnVudGltZV9sb2dnaW5nIDo9IGRhdGEuZnJhbWV3b3JrLnJ1bnRpbWVfbG9nZ2luZwpsb2FkX2ZyYWdtZW50IDo9IGRhdGEuZnJhbWV3b3JrLmxvYWRfZnJhZ21lbnQKc2NyYXRjaF9tb3VudCA6PSBkYXRhLmZyYW1ld29yay5zY3JhdGNoX21vdW50CnNjcmF0Y2hfdW5tb3VudCA6PSBkYXRhLmZyYW1ld29yay5zY3JhdGNoX3VubW91bnQKCnJlYXNvbiA6PSB7ImVycm9ycyI6IGRhdGEuZnJhbWV3b3JrLmVycm9yc30="

        # deep diff the output policies from the regular policy.json and the ARM template
        aci_policy_str = self.aci_policy.get_serialized_output()
        self.assertEqual(aci_policy_str, expected_policy)


# @unittest.skip("not in use")
@pytest.mark.run(order=2)
class PolicyGeneratingImageSidecar(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with load_policy_from_image_name(
            "mcr.microsoft.com/aci/atlas-mount-azure-file-volume:master_20201210.2"
        ) as aci_policy:
            aci_policy.populate_policy_content_for_all_images(individual_image=True)
            cls.aci_policy = aci_policy

    def test_sidecar_image_policy(self):
        expected_policy = "cGFja2FnZSBtaWNyb3NvZnRjb250YWluZXJpbnN0YW5jZQoKYXBpX3ZlcnNpb24gOj0gIjAuMTAuMCIKZnJhbWV3b3JrX3ZlcnNpb24gOj0gIjAuMi4zIgoKY29udGFpbmVycyA6PSBbeyJhbGxvd19lbGV2YXRlZCI6dHJ1ZSwiYWxsb3dfc3RkaW9fYWNjZXNzIjp0cnVlLCJjYXBhYmlsaXRpZXMiOnsiYW1iaWVudCI6W10sImJvdW5kaW5nIjpbIkNBUF9BVURJVF9XUklURSIsIkNBUF9DSE9XTiIsIkNBUF9EQUNfT1ZFUlJJREUiLCJDQVBfRk9XTkVSIiwiQ0FQX0ZTRVRJRCIsIkNBUF9LSUxMIiwiQ0FQX01LTk9EIiwiQ0FQX05FVF9CSU5EX1NFUlZJQ0UiLCJDQVBfTkVUX1JBVyIsIkNBUF9TRVRGQ0FQIiwiQ0FQX1NFVEdJRCIsIkNBUF9TRVRQQ0FQIiwiQ0FQX1NFVFVJRCIsIkNBUF9TWVNfQ0hST09UIl0sImVmZmVjdGl2ZSI6WyJDQVBfQVVESVRfV1JJVEUiLCJDQVBfQ0hPV04iLCJDQVBfREFDX09WRVJSSURFIiwiQ0FQX0ZPV05FUiIsIkNBUF9GU0VUSUQiLCJDQVBfS0lMTCIsIkNBUF9NS05PRCIsIkNBUF9ORVRfQklORF9TRVJWSUNFIiwiQ0FQX05FVF9SQVciLCJDQVBfU0VURkNBUCIsIkNBUF9TRVRHSUQiLCJDQVBfU0VUUENBUCIsIkNBUF9TRVRVSUQiLCJDQVBfU1lTX0NIUk9PVCJdLCJpbmhlcml0YWJsZSI6W10sInBlcm1pdHRlZCI6WyJDQVBfQVVESVRfV1JJVEUiLCJDQVBfQ0hPV04iLCJDQVBfREFDX09WRVJSSURFIiwiQ0FQX0ZPV05FUiIsIkNBUF9GU0VUSUQiLCJDQVBfS0lMTCIsIkNBUF9NS05PRCIsIkNBUF9ORVRfQklORF9TRVJWSUNFIiwiQ0FQX05FVF9SQVciLCJDQVBfU0VURkNBUCIsIkNBUF9TRVRHSUQiLCJDQVBfU0VUUENBUCIsIkNBUF9TRVRVSUQiLCJDQVBfU1lTX0NIUk9PVCJdfSwiY29tbWFuZCI6WyIvbW91bnRfYXp1cmVfZmlsZS5zaCJdLCJlbnZfcnVsZXMiOlt7InBhdHRlcm4iOiJQQVRIPS91c3IvbG9jYWwvc2JpbjovdXNyL2xvY2FsL2JpbjovdXNyL3NiaW46L3Vzci9iaW46L3NiaW46L2JpbiIsInJlcXVpcmVkIjpmYWxzZSwic3RyYXRlZ3kiOiJzdHJpbmcifV0sImV4ZWNfcHJvY2Vzc2VzIjpbXSwiaWQiOiJtY3IubWljcm9zb2Z0LmNvbS9hY2kvYXRsYXMtbW91bnQtYXp1cmUtZmlsZS12b2x1bWU6bWFzdGVyXzIwMjAxMjEwLjIiLCJsYXllcnMiOlsiNjA2ZmQ2YmFmNWViMWE3MWZkMjg2YWVhMjk2NzJhMDZiZmU1NWYwMDA3ZGVkOTJlZTczMTQyYTM3NTkwZWQxOSIsIjNhZDFhMmZmNGE0NGJjODYwYjNjZDAyN2NjODZjZTQ1YTM5OWM0Yzk5NWMzNmU5ODAwYzUzNjhjYjcyN2E3ZTEiLCJiMWNmYzMwZjM3ZjA4ZTYwNjY4ZGIzZjcxNjA2OTdiMTlkMmFkNDViMTJmMDc1MTg4NTI5OTM3MzYxNmE2ZTBhIiwiZWYzNjQ4NDZjOGYxZjQzZDE0ZDJlM2U3OTE5YTA2NGIwYzgyNTUzYzA4YjM1NDIyZjVkMWYwN2MzNDM1YjQ2MiIsIjU4MmZlMzliZDM1OTA5YmFmNmM0MDM2NzM0ZTIwZjc2NjM5MWJhODM3MjdmYjFkNjgzYmUwNDVmZTQ1M2I1YWYiLCJhYWM5ZmI0MDQyNThjMDY5YWU4NTM4MjM2NGY1ZDJiYTFkNDA1MThjNmIxZjU2YWRlNmJjMjJmMzAyOGVhZmYwIl0sIm1vdW50cyI6W10sIm5vX25ld19wcml2aWxlZ2VzIjpmYWxzZSwic2VjY29tcF9wcm9maWxlX3NoYTI1NiI6IiIsInNpZ25hbHMiOltdLCJ1c2VyIjp7Imdyb3VwX2lkbmFtZXMiOlt7InBhdHRlcm4iOiIiLCJzdHJhdGVneSI6ImFueSJ9XSwidW1hc2siOiIwMDIyIiwidXNlcl9pZG5hbWUiOnsicGF0dGVybiI6IiIsInN0cmF0ZWd5IjoiYW55In19LCJ3b3JraW5nX2RpciI6Ii8ifV0="
        aci_policy_str = self.aci_policy.get_serialized_output()
        
        self.assertEqual(aci_policy_str, expected_policy)


# @unittest.skip("not in use")
@pytest.mark.run(order=3)
class PolicyGeneratingImageInvalid(unittest.TestCase):
    def test_invalid_image_policy(self):

        policy = load_policy_from_image_name(
            "mcr.microsoft.com/aci/fake-image:master_20201210.2"
        )
        with self.assertRaises(SystemExit) as exc_info:
            policy.populate_policy_content_for_all_images(individual_image=True)
        self.assertEqual(exc_info.exception.code, 1)


# @unittest.skip("not in use")
@pytest.mark.run(order=4)
class PolicyGeneratingImageCleanRoom(unittest.TestCase):
    def test_clean_room_policy(self):
        client = docker.from_env()
        original_image = (
            "mcr.microsoft.com/aci/atlas-mount-azure-file-volume:master_20201210.2"
        )
        try:
            client.images.remove(original_image)
        except:
            # do nothing
            pass
        regular_image = load_policy_from_image_name(original_image)
        regular_image.populate_policy_content_for_all_images(individual_image=True)
        # create and tag same image to the new name to see if docker will error out that the image is not in a remote repo
        new_repo = "mcr.microsoft.com"
        new_image_name = "aci/atlas-mount-azure-file-volume"
        new_tag = "fake-tag"

        image = client.images.get(original_image)
        try:
            client.images.remove(new_repo + "/" + new_image_name + ":" + new_tag)
        except:
            # do nothing
            pass
        image.tag(new_repo + "/" + new_image_name, tag=new_tag)
        try:
            client.images.remove(original_image)
        except:
            # do nothing
            pass
        client.close()

        policy = load_policy_from_image_name(
            new_repo + "/" + new_image_name + ":" + new_tag
        )
        policy.populate_policy_content_for_all_images(individual_image=True)

        regular_image_json = json.loads(
            regular_image.get_serialized_output(output_type=OutputType.RAW, use_json=True)
        )

        clean_room_json = json.loads(
            policy.get_serialized_output(output_type=OutputType.RAW, use_json=True)
        )

        regular_image_json[config.POLICY_FIELD_CONTAINERS][
            config.POLICY_FIELD_CONTAINERS_ELEMENTS
        ]["0"].pop(config.POLICY_FIELD_CONTAINERS_ID)
        clean_room_json[config.POLICY_FIELD_CONTAINERS][
            config.POLICY_FIELD_CONTAINERS_ELEMENTS
        ]["0"].pop(config.POLICY_FIELD_CONTAINERS_ID)

        # see if the remote image and the local one produce the same output
        self.assertEqual(
            deepdiff.DeepDiff(regular_image_json, clean_room_json, ignore_order=True),
            {},
        )
