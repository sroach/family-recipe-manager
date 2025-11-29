package gy.roach.family.recipe.manager.web

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.core.Authentication
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.ResponseBody

@Controller
class HomeController {

    @GetMapping("/user-info")
    @ResponseBody
    fun userInfo(@AuthenticationPrincipal principal: OidcUser?): ResponseEntity<Map<String, Any?>> {
        return principal?.let {
            ResponseEntity.ok(
                mapOf(
                    "username" to (it.preferredUsername ?: it.name),
                    "email" to it.email,
                    "authorities" to it.authorities.map { auth -> auth.authority },
                    "authenticated" to true
                )
            )
        } ?: ResponseEntity.ok(mapOf("authenticated" to false))
    }

    @GetMapping("/data")
    @PreAuthorize("hasAuthority('SCOPE_write')")
    fun getData(@AuthenticationPrincipal principal: OidcUser): ResponseEntity<ApiResponse<List<DataItem>>> {
        val data = listOf(
            DataItem(1, "Item 1", "Description for ${principal?.name}"),
            DataItem(2, "Item 2", "Another protected item"),
            DataItem(3, "Item 3", "More data here")
        )

        return ResponseEntity.ok(
            ApiResponse(
                success = true,
                data = data,
                message = "Data fetched successfully"
            )
        )
    }
    @GetMapping("/debug-auth")
    @ResponseBody
    fun debugAuth(authentication: Authentication?): Map<String, Any?> {
        return mapOf(
            "authenticated" to (authentication?.isAuthenticated ?: false),
            "principal" to authentication?.principal?.toString(),
            "authorities" to authentication?.authorities?.map { it.authority },
            "name" to authentication?.name
        )
    }
    @GetMapping("/user/profile")
    fun userProfile(@AuthenticationPrincipal principal: OidcUser?): ResponseEntity<ApiResponse<UserProfile>> {
        return principal?.let {
            ResponseEntity.ok(
                ApiResponse(
                    success = true,
                    data = UserProfile(
                        username = it.preferredUsername ?: it.name,
                        email = it.email,
                        givenName = it.givenName,
                        familyName = it.familyName,
                        authorities = it.authorities.map { auth -> auth.authority.toString() }
                    ),
                    message = "Profile fetched successfully"
                )
            )
        } ?: ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
            ApiResponse(
                success = false,
                data = null,
                message = "User not authenticated"
            )
        )
    }

    @PostMapping("/recipes")
    @ResponseBody
    @PreAuthorize("hasAuthority('SCOPE_write')")
    fun createRecipe(@RequestBody recipe: Recipe): ResponseEntity<Recipe> {
        // Only users with SCOPE_write can access this
        return ResponseEntity.ok(recipe)
    }
}

data class Recipe(val id: Long, val name: String, val description: String)

data class DataItem(
    val id: Long,
    val name: String,
    val description: String
)
data class ApiResponse<T>(
    val success: Boolean,
    val data: T?,
    val message: String
)
data class UserProfile(
    val username: String,
    val email: String?,
    val givenName: String?,
    val familyName: String?,
    val authorities: List<String>
)